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
    // Güvenli Key Kontrolü (Uygulamanın çökmesini önler)
    var jwtKey = jwtSettings["Key"] ?? "pLw3V!zJg7^2qK0xD8mR4tY1uC6bN9fQ5sH3kL0wX2yZ8rT6vB1nM4pQ7sU2dE9";
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
    // Downstream Health Check Endpoint (DÜZELTİLDİ - DOCKER İSİMLERİ)
    // ============================================================================
    app.MapGet("/health/downstream", async (IConfiguration configuration, IHttpClientFactory httpClientFactory) =>
    {
        var httpClient = httpClientFactory.CreateClient("HealthCheck");

        // KRİTİK DÜZELTME: localhost yerine Docker içindeki servis isimleri kullanılıyor
        var services = new Dictionary<string, string>
        {
            ["identity"] = configuration["DownstreamServices:Identity"] ?? "http://identity-service:80",
            ["venue"] = configuration["DownstreamServices:Venue"] ?? "http://venue-service:80",
            ["social"] = configuration["DownstreamServices:Social"] ?? "http://social-service:80",
            ["review"] = configuration["DownstreamServices:Review"] ?? "http://review-service:80",
            ["admin"] = configuration["DownstreamServices:Admin"] ?? "http://admin-service:80"
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
        body {{ font-family: -apple-system, sans-serif; background: #1a1a2e; color: #fff; padding: 40px; }}
        a {{ color: #00ff88; }}
    </style>
</head>
<body>
    <h1>🏙️ CityDiscovery API Gateway is Running!</h1>
    <p>Go to <a href=""{baseUrl}/health"">Health Check</a> to see status.</p>
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