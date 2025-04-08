# Backend

For putting the Docker container up:

docker compose up --build

For putting all down:

First:

docker compose down -v

Second:

docker system prune -a --volumes

## API Endpoints

### `/ask/{file_id}`

This endpoint allows users to ask questions about their uploaded documents and receive AI-generated answers based on the document content.

**How it works:**

1. **Authentication**: The endpoint requires a valid JWT token obtained through login.

2. **Document Retrieval**: The system retrieves the document by its ID and verifies that the requesting user is the owner.

3. **Content Extraction**: The system extracts text content from the document's embeddings, which are created during document processing.

4. **Context Building**: The extracted text chunks are combined to create a context that the AI model can use to generate relevant answers.

5. **AI Processing**: The question and document context are sent to the OpenRouter API (using the Llama 4 Maverick model) to generate a contextually relevant answer.

6. **Response**: The generated answer is returned to the user.

**Error Handling:**

- Returns 404 if the document is not found or doesn't belong to the user
- Returns 400 if document embeddings are not yet available (processing incomplete)
- Returns 500 if there's an issue with the OpenRouter API call
