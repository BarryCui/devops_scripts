from openai import OpenAI

"""
deepseek推理模型的单论对话脚本。运行脚本，然后输入问题，程序会流式打印思考过程和推理结果。
api替换成自己的。

python basic_chat.py
"""

client = OpenAI(api_key="<api>", base_url="https://api.deepseek.com")

# Round 1
user_input = input("content: ")
messages = [{"role": "user", "content": user_input}]
response = client.chat.completions.create(
    model="deepseek-reasoner",
    messages=messages,
    stream=True
)

GREEN = '\033[92m'
RESET = '\033[0m'

reasoning_content = ""
content = ""

for chunk in response:
    if chunk.choices[0].delta.reasoning_content:
        reasoning_content = chunk.choices[0].delta.reasoning_content or ""
        print(f"{GREEN}{reasoning_content}{RESET}", end="", flush=True)
    else:
        content = chunk.choices[0].delta.content or ""
        print(content, end="", flush=True)
