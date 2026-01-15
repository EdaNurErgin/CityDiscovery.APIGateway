using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.IdentityModel.Tokens;
using Serilog;
using Serilog.Events;
using System.Text;
using System.Threading.RateLimiting;
using Yarp.ReverseProxy.Transforms;

// ============================================================================
// Serilog Bootstrap Logger
// ============================================================================
Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Override("Microsoft", LogEventLevel.Information)
    .Enrich.FromLogContext()
    .WriteTo.Console()
    .CreateBootstrapLogger();

try
{
    Log.Information("Starting CityDiscovery API Gateway...");

    var builder = WebApplication.CreateBuilder(args);

    // ============================================================================
    // Serilog Configuration
    // ============================================================================
    builder.Host.UseSerilog((context, services, configuration) => configuration
        .ReadFrom.Configuration(context.Configuration)
        .ReadFrom.Services(services)
        .Enrich.FromLogContext()
        .Enrich.WithProperty("Application", "CityDiscovery.ApiGateway")
        .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] [{CorrelationId}] {Message:lj}{NewLine}{Exception}"));

    // ============================================================================
    // JWT Authentication Configuration
    // ============================================================================
    var jwtSettings = builder.Configuration.GetSection("Jwt");
    var jwtKey = jwtSettings["Key"] ?? throw new InvalidOperationException("JWT Key is not configured");
    var jwtIssuer = jwtSettings["Issuer"] ?? "identity";
    var jwtAudience = jwtSettings["Audience"] ?? "citydiscovery";

    builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
        .AddJwtBearer(options =>
        {
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = jwtIssuer,
                ValidAudience = jwtAudience,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),
                ClockSkew = TimeSpan.FromMinutes(5)
            };

            options.Events = new JwtBearerEvents
            {
                OnAuthenticationFailed = context =>
                {
                    Log.Warning("JWT Authentication failed: {Error}", context.Exception.Message);
                    return Task.CompletedTask;
                },
                OnTokenValidated = context =>
                {
                    Log.Debug("JWT Token validated for user: {User}", context.Principal?.Identity?.Name);
                    return Task.CompletedTask;
                }
            };
        });

    // ============================================================================
    // Authorization Policies
    // ============================================================================
    builder.Services.AddAuthorization(options =>
    {
        options.AddPolicy("RequireAuthenticatedUser", policy =>
            policy.RequireAuthenticatedUser());

        options.AddPolicy("RequireAdminRole", policy =>
            policy.RequireRole("Admin"));

        options.AddPolicy("RequireOwnerRole", policy =>
            policy.RequireRole("Owner", "Admin"));

        options.AddPolicy("Anonymous", policy =>
            policy.RequireAssertion(_ => true));
    });

    // ============================================================================
    // Rate Limiting Configuration
    // ============================================================================
    var rateLimitConfig = builder.Configuration.GetSection("RateLimiting");
    var permitLimit = rateLimitConfig.GetValue<int>("PermitLimit", 100);
    var windowSeconds = rateLimitConfig.GetValue<int>("WindowSeconds", 60);
    var queueLimit = rateLimitConfig.GetValue<int>("QueueLimit", 2);

    builder.Services.AddRateLimiter(options =>
    {
        options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

        options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(httpContext =>
            RateLimitPartition.GetFixedWindowLimiter(
                partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "anonymous",
                factory: partition => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = permitLimit,
                    Window = TimeSpan.FromSeconds(windowSeconds),
                    QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                    QueueLimit = queueLimit
                }));

        options.OnRejected = async (context, token) =>
        {
            context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
            Log.Warning("Rate limit exceeded for IP: {IP}", context.HttpContext.Connection.RemoteIpAddress);

            await context.HttpContext.Response.WriteAsJsonAsync(new
            {
                error = "Too many requests. Please try again later.",
                retryAfter = windowSeconds
            }, cancellationToken: token);
        };
    });

    // ============================================================================
    // YARP Reverse Proxy Configuration
    // ============================================================================
    builder.Services.AddReverseProxy()
        .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
        .AddTransforms(transformBuilderContext =>
        {
            // Add X-Forwarded headers for downstream services
            transformBuilderContext.AddXForwarded();

            // Forward the correlation ID to downstream services
            transformBuilderContext.AddRequestTransform(async context =>
            {
                if (context.HttpContext.Items.TryGetValue("CorrelationId", out var correlationId))
                {
                    context.ProxyRequest?.Headers.TryAddWithoutValidation("X-Correlation-Id", correlationId?.ToString());
                }
                await Task.CompletedTask;
            });
        });

    // ============================================================================
    // Swagger/OpenAPI for Gateway Endpoints
    // ============================================================================
    builder.Services.AddEndpointsApiExplorer();
    builder.Services.AddSwaggerGen(options =>
    {
        options.SwaggerDoc("v1", new Microsoft.OpenApi.Models.OpenApiInfo
        {
            Title = "CityDiscovery API Gateway",
            Version = "v1",
            Description = "API Gateway for CityDiscovery Microservices"
        });
    });

    // ============================================================================
    // Health Checks
    // ============================================================================
    builder.Services.AddHealthChecks();

    // ============================================================================
    // HttpClient for downstream health checks
    // ============================================================================
    builder.Services.AddHttpClient("HealthCheck", client =>
    {
        client.Timeout = TimeSpan.FromSeconds(5);
    });

    // ============================================================================
    // CORS Configuration (for future frontend usage)
    // ============================================================================
    builder.Services.AddCors(options =>
    {
        options.AddPolicy("AllowAll", policy =>
        {
            policy.AllowAnyOrigin()
                  .AllowAnyMethod()
                  .AllowAnyHeader();
        });
    });

    var app = builder.Build();

    // ============================================================================
    // Correlation ID Middleware
    // ============================================================================
    app.Use(async (context, next) =>
    {
        var correlationId = context.Request.Headers["X-Correlation-Id"].FirstOrDefault()
                            ?? Guid.NewGuid().ToString();

        context.Items["CorrelationId"] = correlationId;
        context.Response.Headers["X-Correlation-Id"] = correlationId;

        using (Serilog.Context.LogContext.PushProperty("CorrelationId", correlationId))
        {
            await next();
        }
    });

    // ============================================================================
    // Request Logging Middleware
    // ============================================================================
    app.UseSerilogRequestLogging(options =>
    {
        options.EnrichDiagnosticContext = (diagnosticContext, httpContext) =>
        {
            diagnosticContext.Set("CorrelationId", httpContext.Items["CorrelationId"]?.ToString());
            diagnosticContext.Set("ClientIP", httpContext.Connection.RemoteIpAddress?.ToString());
        };
    });

    // ============================================================================
    // Swagger UI
    // ============================================================================
    app.UseSwagger();
    app.UseSwaggerUI(options =>
    {
        options.SwaggerEndpoint("/swagger/v1/swagger.json", "CityDiscovery API Gateway v1");
        options.RoutePrefix = "swagger";
    });

    // ============================================================================
    // CORS
    // ============================================================================
    app.UseCors("AllowAll");

    // ============================================================================
    // Rate Limiting
    // ============================================================================
    app.UseRateLimiter();

    // ============================================================================
    // Authentication & Authorization
    // ============================================================================
    app.UseAuthentication();
    app.UseAuthorization();

    // ============================================================================
    // Gateway Health Endpoint
    // ============================================================================
    app.MapGet("/health", () => Results.Ok(new
    {
        status = "Healthy",
        service = "CityDiscovery.ApiGateway",
        timestamp = DateTime.UtcNow
    }))
    .WithName("HealthCheck")
    .WithTags("Health")
    .AllowAnonymous();

    // ============================================================================
    // Downstream Health Check Endpoint
    // ============================================================================
    app.MapGet("/health/downstream", async (IConfiguration configuration, IHttpClientFactory httpClientFactory) =>
    {
        var httpClient = httpClientFactory.CreateClient("HealthCheck");
        var services = new Dictionary<string, string>
        {
            ["identity"] = configuration["DownstreamServices:Identity"] ?? "http://host.docker.internal:5001",
            ["venue"] = configuration["DownstreamServices:Venue"] ?? "http://venue-service",
            ["social"] = configuration["DownstreamServices:Social"] ?? "http://social-service",
            ["review"] = configuration["DownstreamServices:Review"] ?? "http://review-service",
            ["admin"] = configuration["DownstreamServices:Admin"] ?? "http://admin-service"
        };

        var healthResults = new Dictionary<string, object>();

        foreach (var (name, baseUrl) in services)
        {
            try
            {
                var response = await httpClient.GetAsync($"{baseUrl}/health");
                healthResults[name] = new
                {
                    status = response.IsSuccessStatusCode ? "Healthy" : "Unhealthy",
                    statusCode = (int)response.StatusCode,
                    url = baseUrl
                };
            }
            catch (Exception ex)
            {
                healthResults[name] = new
                {
                    status = "Unreachable",
                    error = ex.Message,
                    url = baseUrl
                };
            }
        }

        var allHealthy = healthResults.Values.Cast<dynamic>().All(v => v.status == "Healthy");

        return Results.Ok(new
        {
            status = allHealthy ? "AllHealthy" : "Degraded",
            timestamp = DateTime.UtcNow,
            services = healthResults
        });
    })
    .WithName("DownstreamHealthCheck")
    .WithTags("Health")
    .AllowAnonymous();

    // ============================================================================
    // Swagger UI Links Page (/docs)
    // ============================================================================
    app.MapGet("/docs", (HttpContext context) =>
    {
        var baseUrl = $"{context.Request.Scheme}://{context.Request.Host}";

        var html = $@"
<!DOCTYPE html>
<html lang=""en"">
<head>
    <meta charset=""UTF-8"">
    <meta name=""viewport"" content=""width=device-width, initial-scale=1.0"">
    <title>CityDiscovery API Documentation</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            color: #fff;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 40px 20px;
        }}
        h1 {{
            font-size: 2.5rem;
            margin-bottom: 10px;
            background: linear-gradient(90deg, #00d9ff, #00ff88);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .subtitle {{
            color: #8892b0;
            font-size: 1.1rem;
            margin-bottom: 40px;
        }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 24px;
        }}
        .card {{
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 16px;
            padding: 24px;
            transition: all 0.3s ease;
        }}
        .card:hover {{
            transform: translateY(-4px);
            background: rgba(255, 255, 255, 0.08);
            border-color: #00d9ff;
        }}
        .card h3 {{
            font-size: 1.25rem;
            margin-bottom: 8px;
            color: #00d9ff;
        }}
        .card p {{
            color: #8892b0;
            margin-bottom: 16px;
            font-size: 0.9rem;
        }}
        .links {{
            display: flex;
            flex-direction: column;
            gap: 8px;
        }}
        .links a {{
            color: #00ff88;
            text-decoration: none;
            padding: 8px 12px;
            background: rgba(0, 255, 136, 0.1);
            border-radius: 8px;
            font-size: 0.85rem;
            transition: all 0.2s ease;
        }}
        .links a:hover {{
            background: rgba(0, 255, 136, 0.2);
        }}
        .badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.7rem;
            font-weight: 600;
            text-transform: uppercase;
            margin-bottom: 12px;
        }}
        .badge.public {{ background: #00ff88; color: #1a1a2e; }}
        .badge.protected {{ background: #ff6b6b; color: #fff; }}
        .badge.gateway {{ background: #00d9ff; color: #1a1a2e; }}
        .status {{
            margin-top: 30px;
            padding: 20px;
            background: rgba(255, 255, 255, 0.03);
            border-radius: 12px;
        }}
        .status a {{
            color: #00ff88;
            text-decoration: none;
        }}
    </style>
</head>
<body>
    <div class=""container"">
        <h1>🏙️ CityDiscovery API Gateway</h1>
        <p class=""subtitle"">Unified API documentation hub for all microservices</p>

        <div class=""grid"">
            <div class=""card"">
                <span class=""badge gateway"">Gateway</span>
                <h3>API Gateway</h3>
                <p>Gateway endpoints including health checks and this documentation page</p>
                <div class=""links"">
                    <a href=""{baseUrl}/swagger"" target=""_blank"">📘 Gateway Swagger UI</a>
                    <a href=""{baseUrl}/health"" target=""_blank"">❤️ Gateway Health</a>
                    <a href=""{baseUrl}/health/downstream"" target=""_blank"">🔍 Downstream Health</a>
                </div>
            </div>

            <div class=""card"">
                <span class=""badge public"">Public</span>
                <h3>🔐 Identity Service</h3>
                <p>Authentication, registration, and user management (auth routes are public)</p>
                <div class=""links"">
                    <a href=""{baseUrl}/swagger/identity/index.html"" target=""_blank"">📘 Identity Swagger UI</a>
                    <a href=""http://localhost:5001/swagger"" target=""_blank"">📘 Direct (localhost:5001)</a>
                </div>
            </div>

            <div class=""card"">
                <span class=""badge protected"">Protected</span>
                <h3>📍 Venue Service</h3>
                <p>Manage venues, locations, and venue-related operations</p>
                <div class=""links"">
                    <a href=""{baseUrl}/swagger/venue/index.html"" target=""_blank"">📘 Venue Swagger UI</a>
                    <a href=""http://localhost:5002/swagger"" target=""_blank"">📘 Direct (localhost:5002)</a>
                </div>
            </div>

            <div class=""card"">
                <span class=""badge protected"">Protected</span>
                <h3>👥 Social Service</h3>
                <p>Social features, posts, and user interactions</p>
                <div class=""links"">
                    <a href=""{baseUrl}/swagger/social/index.html"" target=""_blank"">📘 Social Swagger UI</a>
                    <a href=""http://localhost:5003/swagger"" target=""_blank"">📘 Direct (localhost:5003)</a>
                </div>
            </div>

            <div class=""card"">
                <span class=""badge protected"">Protected</span>
                <h3>⭐ Review Service</h3>
                <p>Venue reviews, ratings, and feedback management</p>
                <div class=""links"">
                    <a href=""{baseUrl}/swagger/review/index.html"" target=""_blank"">📘 Review Swagger UI</a>
                    <a href=""http://localhost:5004/swagger"" target=""_blank"">📘 Direct (localhost:5004)</a>
                </div>
            </div>

            <div class=""card"">
                <span class=""badge protected"">Protected</span>
                <h3>🔧 Admin Service</h3>
                <p>Administration and notification management</p>
                <div class=""links"">
                    <a href=""{baseUrl}/swagger/admin/index.html"" target=""_blank"">📘 Admin Swagger UI</a>
                    <a href=""http://localhost:5005/swagger"" target=""_blank"">📘 Direct (localhost:5005)</a>
                </div>
            </div>
        </div>

        <div class=""status"">
            <h3 style=""margin-bottom: 12px;"">📊 Quick Status Check</h3>
            <p>Check <a href=""{baseUrl}/health/downstream"">downstream service health</a> to verify all services are running.</p>
        </div>
    </div>
</body>
</html>";

        return Results.Content(html, "text/html");
    })
    .WithName("DocsPage")
    .WithTags("Documentation")
    .AllowAnonymous()
    .ExcludeFromDescription();

    // ============================================================================
    // YARP Authorization Middleware
    // ============================================================================
    app.MapReverseProxy(proxyPipeline =>
    {
        proxyPipeline.Use(async (context, next) =>
        {
            var route = context.GetRouteModel();
            var authPolicy = route.Config?.Metadata?.GetValueOrDefault("AuthorizationPolicy", "RequireAuthenticatedUser");

            if (authPolicy == "RequireAuthenticatedUser")
            {
                // Check if user is authenticated
                if (!context.User.Identity?.IsAuthenticated ?? true)
                {
                    Log.Warning("Unauthorized access attempt to route: {Path}", context.Request.Path);
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    await context.Response.WriteAsJsonAsync(new
                    {
                        error = "Unauthorized",
                        message = "A valid JWT token is required to access this resource"
                    });
                    return;
                }
            }

            await next();
        });
    });

    Log.Information("CityDiscovery API Gateway is running on http://localhost:5000");
    app.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "API Gateway terminated unexpectedly");
}
finally
{
    Log.CloseAndFlush();
}
