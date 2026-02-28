FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
EXPOSE 80
ENV ASPNETCORE_URLS=http://+:80
ENV ASPNETCORE_ENVIRONMENT=Production

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src


COPY ["CityDiscovery.APIGateway/CityDiscovery.APIGateway.csproj", "CityDiscovery.APIGateway/"]
RUN dotnet restore "CityDiscovery.APIGateway/CityDiscovery.APIGateway.csproj"

COPY . .


WORKDIR "/src/CityDiscovery.APIGateway"
RUN dotnet build "CityDiscovery.APIGateway.csproj" -c $BUILD_CONFIGURATION -o /app/build

FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "CityDiscovery.APIGateway.csproj" -c $BUILD_CONFIGURATION -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .


HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl --fail http://localhost:80/health || exit 1

ENTRYPOINT ["dotnet", "CityDiscovery.APIGateway.dll"]