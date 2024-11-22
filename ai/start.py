from llama_cpp import Llama
import sys
from typing import Generator
import time

class WhiteRabbitLLM:
    def __init__(self):
        try:
            self.llm = Llama(
                model_path="models/whiterabbitneo-13b.Q4_K_M.gguf",
                n_ctx=512,
                n_batch=256,
                n_threads=1,
                use_mlock=True
            )
        except Exception as e:
            print(f"Error loading model: {e}")
            sys.exit(1)

    def get_streaming_response(self, prompt: str, max_tokens: int = 128) -> Generator[str, None, None]:
        try:
            stream = self.llm(
                prompt,
                max_tokens=max_tokens,
                temperature=0.8,
                top_p=0.95,
                repeat_penalty=1.0,
                top_k=40,
                stream=True
            )
            
            for output in stream:
                yield output['choices'][0]['text']
                
        except Exception as e:
            yield f"Error generating response: {e}"

def print_slowly(text: str, delay: float = 0.01):
    """Print text character by character"""
    for char in text:
        print(char, end='', flush=True)
        time.sleep(delay)

def main():
    # Initialize model
    print("Loading WhiteRabbit LLM...")
    model = WhiteRabbitLLM()
    
    print("WhiteRabbit LLM initialized. Type 'quit' to exit.")
    print("-" * 50)
    
    # Interactive loop
    while True:
        try:
            # Get user input
            user_input = input("\nYou: ").strip()
            
            # Check for quit command
            if user_input.lower() in ['quit', 'exit']:
                print("Shutting down...")
                break
            
            # Get and print streaming response
            if user_input:
                print("\nWhiteRabbit: ", end='')
                for text_chunk in model.get_streaming_response(user_input):
                    print_slowly(text_chunk)
                print()  # New line after response
                
        except KeyboardInterrupt:
            print("\nShutting down...")
            break
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    main()