"""Quick connectivity check: confirms GROQ_API_KEY works before running the pipeline."""
import os

from dotenv import load_dotenv
from langchain_groq import ChatGroq

load_dotenv()
model = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")
response = ChatGroq(model=model).invoke("Respond with one word: working")
print(f"{model}: {response.content}")
