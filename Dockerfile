# build environment
FROM golang:1.18-alpine as build
RUN mkdir -vp /app
COPY ./go.mod /app/go.mod
COPY ./go.sum /app/go.sum
COPY ./apis /app/apis
COPY ./authenticate /app/authenticate
COPY ./common /app/common
COPY ./match /app/match
COPY ./models /app/models
COPY ./users /app/users
COPY ./main.go /app/main.go
RUN cd /app && \
    go build -o padlock.bin . && \
    cp -v ./padlock.bin /usr/bin/

# production environment
FROM alpine
COPY --from=build /usr/bin/padlock.bin /usr/bin/
ENTRYPOINT ["/usr/bin/padlock.bin"]
