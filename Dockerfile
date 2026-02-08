# 1. Use the lightweight python:3.9-slim base image 
FROM python:3.9-slim

# 2. Set the working directory inside the container
WORKDIR /app

# 3. Copy requirements.txt and install dependencies [cite: 145]
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 4. Copy the application code into the container [cite: 145]
COPY . .

RUN useradd -m security_user
#--New steps for permission issue--
# Create a temp directory and give onwrship to the new user
RUN mkdir -p /app/temp && chown -R security_user:security_user /app
# 5. Security Step: Create a non-root user and switch to it 
# This prevents the app from having root access to the container or host

USER security_user

# 6. Expose the port Streamlit uses (default is 8501)
EXPOSE 8501

# 7. Define the command to run the application 
CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]