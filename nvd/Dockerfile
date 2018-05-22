FROM golang:1.10.1-alpine3.7

MAINTAINER maiconscosta@gmail.com

# Install dependencies
RUN apk update && apk upgrade && \
    apk add --no-cache bash git openssh build-base

# Install Go Dep
RUN go get -u github.com/golang/dep/cmd/dep

# Install go-cve-dictionary
RUN go get -d github.com/kotakanbe/go-cve-dictionary
WORKDIR $GOPATH/src/github.com/kotakanbe/go-cve-dictionary
RUN dep status
RUN dep ensure -v
RUN go install

# Mount startup script
WORKDIR /db
ADD bin/startup.sh /bin/startup.sh
CMD startup.sh
