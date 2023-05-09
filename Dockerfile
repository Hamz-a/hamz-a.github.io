# syntax=docker/dockerfile:1.2

FROM --platform=linux/amd64 ruby:alpine
RUN apk add gcc g++ make git
WORKDIR /srv
COPY . .
RUN bundle
CMD [ "jekyll", "serve", "--livereload", "-H", "0.0.0.0" ]
EXPOSE 4000