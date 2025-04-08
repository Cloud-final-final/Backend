import os
import requests
import json
from dotenv import load_dotenv
import sys

# Load environment variables from .env file
load_dotenv()

# Get API key from environment variables - use the exact key from the .env file
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
OPENROUTER_API_KEY = str(OPENROUTER_API_KEY)
OPENROUTER_API_KEY = "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"


# Verify API key is available
if not OPENROUTER_API_KEY:
    raise ValueError("OPENROUTER_API_KEY environment variable is not set")

# Print first few characters of API key for debugging (safely)
print(f"Using API key starting with: {OPENROUTER_API_KEY[:8]}...")
print(f"API key length: {len(OPENROUTER_API_KEY)}")


def query_openrouter_multimodal(prompt_text, image_url):
    """Send a multimodal query to OpenRouter API

    Args:
        prompt_text (str): The text prompt to send
        image_url (str): URL of the image to analyze

    Returns:
        dict: The API response
    """
    try:
        # Print full request details for debugging
        headers = {
            "Authorization": f"Bearer {OPENROUTER_API_KEY}",
            "Content-Type": "application/json"
        }

        print("Making request to OpenRouter API...")
        print(f"URL: https://openrouter.ai/api/v1/chat/completions")
        print(
            f"Headers: {json.dumps({k: v if k != 'Authorization' else v for k, v in headers.items()}, indent=2)}")

        response = requests.post(
            url="https://openrouter.ai/api/v1/chat/completions",
            headers=headers,
            data=json.dumps({
                "model": "meta-llama/llama-4-maverick:free",
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "text",
                                "text": prompt_text
                            }
                        ],

                    }
                ],
            }),
            timeout=60  # Set a reasonable timeout
        )

        # Check if the request was successful
        response.raise_for_status()

        return response.json()

    except requests.exceptions.RequestException as e:
        print(f"Error making request: {e}")
        # Print more detailed error information
        if hasattr(e, 'response') and e.response is not None:
            print(f"Response status code: {e.response.status_code}")
            print(f"Response headers: {e.response.headers}")
            print(f"Response content: {e.response.text}")
        return {"error": str(e)}
    except json.JSONDecodeError:
        print("Error decoding JSON response")
        return {"error": "Invalid JSON response"}
    except Exception as e:
        print(f"Unexpected error: {e}")
        return {"error": str(e)}


# Example usage
if __name__ == "__main__":
    # Example image URL
    image_url = "https://upload.wikimedia.org/wikipedia/commons/thumb/d/dd/Gfp-wisconsin-madison-the-nature-boardwalk.jpg/2560px-Gfp-wisconsin-madison-the-nature-boardwalk.jpg"

    # Example prompt
    prompt = "Why started the WWII?"

    # Make the API call
    result = query_openrouter_multimodal(prompt, image_url)

    # Print the result
    if "error" in result:
        print(f"Error: {result['error']}")
    else:
        print("\nAPI Response:")
        print(json.dumps(result, indent=2))

        # Extract and print just the model's response text
        if "choices" in result and len(result["choices"]) > 0:
            model_response = result["choices"][0]["message"]["content"]
            print("\nModel's description of the image:")
            print(model_response)
