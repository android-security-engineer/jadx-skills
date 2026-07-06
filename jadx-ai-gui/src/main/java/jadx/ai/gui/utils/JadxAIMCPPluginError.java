package jadx.ai.gui.utils;

import java.util.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.javalin.http.Context;

public class JadxAIMCPPluginError {

    /**
     * @param ctx The HTTP request context to send error response
     * @param error_response The error message to return to client
     * @param e The exception that caused the error
     * @param logger The logger instance for error logging
     * @return void
     * 
     * This method handles exceptions with full error logging and HTTP 500 response.
     * 1. It logs the error message with the full exception stack trace
     * 2. It sets HTTP status to 500 (Internal Server Error)
     * 3. It sends a JSON response containing the error message
     * 
     * This overload is used when an exception needs to be logged with details.
     */
    public static void handleError(Context ctx, String error_response, Exception e, Logger logger) {
        logger.error("JADX AI MCP Error: " + error_response, e);
        ctx.status(500).json(Map.of("error", error_response));
    }

    /**
     * @param ctx The HTTP request context to send error response
     * @param status The HTTP status code to return
     * @param error_response The error message to return to client
     * @param logger The logger instance for error logging
     * @return void
     * 
     * This method handles errors with custom HTTP status codes.
     * 1. It logs the error message without exception details
     * 2. It sets the specified HTTP status code (e.g., 404, 400)
     * 3. It sends a JSON response containing the error message
     * 
     * This overload is used for validation errors or missing resources
     * where a specific HTTP status code is appropriate.
    */
    public static void handleError(Context ctx, int status, String error_response, Logger logger) {
        logger.error("JADX AI MCP Error: " + error_response);
        ctx.status(status).json(Map.of("error", error_response));
    }
}
