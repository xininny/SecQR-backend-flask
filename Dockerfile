# 첫 번째 스테이지: 빌드 환경
FROM python:3.8-slim AS build

WORKDIR /app

# 필요한 패키지 설치
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 두 번째 스테이지: 실행 환경
FROM python:3.8-slim

WORKDIR /app

# 빌드된 패키지 복사
COPY --from=build /usr/local/lib/python3.8/site-packages /usr/local/lib/python3.8/site-packages
COPY --from=build /usr/local/bin /usr/local/bin

# 애플리케이션 코드 복사
COPY . .

# 환경 변수 설정
ENV PORT=8080


# 애플리케이션 실행
CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:8080", "--timeout", "120", "app:app"]
