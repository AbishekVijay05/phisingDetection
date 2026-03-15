from detectors.gemini_analyzer import analyze_url_with_gemini
import os

# Set a dummy API key if not present, but it won't work for real analysis
# os.environ['GEMINI_API_KEY'] = 'test-key'

result = analyze_url_with_gemini("http://suspicious-site.com")
print(f"Gemini Analysis Result: {result}")
