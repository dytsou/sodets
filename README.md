# Get Started

## Run core-system

Clone backend source code.

```
git clone https://github.com/NYCU-SDC/core-system-backend.git
```

Start a PostgreSQL container, for example:

```
docker run --name db -e POSTGRES_PASSWORD=password -p 5432:5432 -d postgres
```

After the container starts successfully, create a database named `core-system`.\
Configure your settings in `config.yaml`. At minimum, you must provide the `database_url`, for example:

```
database_url: "postgres://postgres:password@localhost:5432/core-system?sslmode=disable"
base_url: "http://localhost:8080"
```

Run the backend:

```
make run
```

If the server starts successfully, visit:

```
http://localhost:8080/api/healthz
```

You should see: `OK` printed on the page.

## Run sodets

```
make build
```

```
docker build -t sodets .
```

```
docker run \
  -p 8081:8081 \
  -v $(pwd)/observability-data:/app/observability-data \
  --name sodets_container \
  sodets

```
