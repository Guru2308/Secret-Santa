FROM golang:1.23.3-bookworm
WORKDIR /app
COPY . .
EXPOSE 8080
CMD [ "go", "run", "." ]
