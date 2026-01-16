# ============================================================================
# CityDiscovery API Gateway - Multi-stage Dockerfile
# ============================================================================

# Stage 1: Build
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copy project file and restore dependencies
COPY ["CityDiscovery.APIGateway.csproj", "./"]
RUN dotnet restore "CityDiscovery.APIGateway.csproj"

# Copy source code and build
COPY . .
RUN dotnet build "CityDiscovery.APIGateway.csproj" -c Release -o /app/build

# Stage 2: Publish
FROM build AS publish
RUN dotnet publish "CityDiscovery.APIGateway.csproj" -c Release -o /app/publish /p:UseAppHost=false

# Stage 3: Runtime
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS final
WORKDIR /app

# Set environment variables
ENV ASPNETCORE_URLS=http://+:80
ENV ASPNETCORE_ENVIRONMENT=Production

# Expose port
EXPOSE 80

# Copy published files
COPY --from=publish /app/publish .

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl --fail http://localhost:80/health || exit 1

# Entry point
ENTRYPOINT ["dotnet", "CityDiscovery.APIGateway.dll"]
