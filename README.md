# blockchain_api

## Session Keys

This API uses gorilla/sessions for secure session management. You must provide two secure random keys as environment variables:

- `SESSION_AUTH_KEY`: Used for session authentication/signing (32 or 64 bytes, base64 encoded)
- `SESSION_ENC_KEY`: Used for session encryption (16, 24, or 32 bytes, base64 encoded)

### Generating Keys

A helper script is provided to generate these keys and store them in a `.env` file:

```bash
bash generate_session_keys.sh
```

This will create a `.env` file with the following content:

```
SESSION_AUTH_KEY=...
SESSION_ENC_KEY=...
```

### Usage in Docker

When running your Docker container, make sure to load the `.env` file so the environment variables are available to your application:

```bash
docker run --env-file .env -p 3000:3000 your-api-image
```

> **Note:** For production, generate these keys once and keep them secret and persistent. If you generate new keys, all previous sessions will become invalid.

## Running with Docker Compose

To build and run the application using Docker Compose:

1. Make sure you have generated the `.env` file with session keys (see the Session Keys section).
2. Run the following command:

```bash
docker-compose up --build
```

This will build the Docker image and start the API service, exposing it on port 3000.

- The application will automatically use the environment variables from your `.env` file.
- To stop the service, use:

```bash
docker-compose down
```