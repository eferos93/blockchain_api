# syntax=docker/dockerfile:1
FROM golang:1.24.3-alpine AS build
WORKDIR /app
RUN apk update && apk upgrade --no-cache
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Build the binary (do not run tests in the Docker build)
RUN go build -o blockchain_api

FROM alpine:3.21
WORKDIR /app
RUN apk update && apk upgrade --no-cache
COPY --from=build /app/blockchain_api ./
COPY --from=build /app/README.md ./
COPY --from=build /app/generate_session_keys.sh ./
COPY --from=build /app/client ./client
COPY --from=build /app/identities ./identities
COPY --from=build /app/.env ./

# Expose the API port
EXPOSE 3000

# Run the application
CMD ["./blockchain_api"]
