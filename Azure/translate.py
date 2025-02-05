import azure.cognitiveservices.speech as speechsdk
from openai import AzureOpenAI
import time
from dotenv import load_dotenv
import os

"""
对接Azure openai api和Azure speech api，实现英文->中文实时翻译。用麦克风说话，脚本就会实时翻译。
需要适当停顿，才能翻译下一句，不要一直说。 实测反应有几秒延迟。
python translate.py
"""
# Read credentials from .env file
load_dotenv()
speech_key = os.getenv("speech_key")
service_region = os.getenv("service_region")
openai_api_key = os.getenv("openai_api_key")
openai_endpoint = os.getenv("openai_endpoint")
deployment_name = os.getenv("deployment_name")

# Initialize clients
openai_client = AzureOpenAI(
    api_key=openai_api_key,
    api_version="2023-12-01-preview",
    azure_endpoint=openai_endpoint
)


def translate_text(text):
    try:
        response = openai_client.chat.completions.create(
            model=deployment_name,
            messages=[{
                "role": "system",
                "content": "You are a translator. Translate English to Chinese. Keep the meaning identical."
            }, {
                "role": "user",
                "content": text
            }],
            temperature=0.7,
            max_tokens=150
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        print(f"Translation error: {str(e)}")
        return "[Translation Failed]"

def recognize_speech():
    # Configure speech recognition
    speech_config = speechsdk.SpeechConfig(subscription=speech_key, region=service_region)
    audio_config = speechsdk.audio.AudioConfig(use_default_microphone=True)
    
    # Configure recognition language
    speech_config.speech_recognition_language = "en-US"
    
    # Create recognizer with detailed logging
    speech_recognizer = speechsdk.SpeechRecognizer(
        speech_config=speech_config,
        audio_config=audio_config
    )

    print("Listening... (Speak clearly into your microphone)")

    def recognized_callback(evt):
        if evt.result.reason == speechsdk.ResultReason.RecognizedSpeech:
            english_text = evt.result.text
            print(f"\nEnglish: {english_text}")
            chinese_translation = translate_text(english_text)
            print(f"Chinese: {chinese_translation}")
        elif evt.result.reason == speechsdk.ResultReason.NoMatch:
            print("(No speech detected - try speaking louder or closer to mic)")

    # Connect callbacks
    speech_recognizer.recognized.connect(recognized_callback)
    
    # Start continuous recognition
    speech_recognizer.start_continuous_recognition()

    # Keep the program running
    try:
        while True:
            time.sleep(0.1)
    except KeyboardInterrupt:
        speech_recognizer.stop_continuous_recognition()

if __name__ == "__main__":
    # Uncomment to list microphones if needed
    # list_microphones()
    
    recognize_speech()
