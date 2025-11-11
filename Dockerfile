FROM python:3.13-slim

WORKDIR /app

# requirements.txt 먼저 복사해서 캐시 최적화
COPY requirements.txt .  
RUN pip install --no-cache-dir -r requirements.txt

# 나머지 소스 복사
COPY . .

# Cloud Run은 기본적으로 8080 포트를 사용
EXPOSE 8080

# FastAPI 실행 (app.py 파일 안의 app 객체를 실행)
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
