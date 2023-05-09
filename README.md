# Hamza's blog posts, notes and thoughts.

## Installation Instructions
### Prerequisites
- Docker Desktop
#### Runtime only
1. Run a container binding the project into its volume
- macOS
```shell
docker run --name bhamza.me -dp 4000:4000 --rm caddydz/hamz-a.github.io && open http://localhost
```
- Windows
```shell
docker run --name bhamza.me -dp 4000:4000 --rm caddydz/hamz-a.github.io && start "http://localhost"
```
#### Development
1. Clone the repository
```shell
git clone https://github.com/Hamz-a/hamz-a.github.io Hamza
```
2. Change into the directory
```shell
cd Hamza
```
3. Build the Docker image
```shell
docker build --no-cache -t caddydz/hamz-a.github.io .
```
4. Run a container binding the project into its volume
```shell
docker run --name bhamza.me -dp 35729:35729 -p 4000:4000 -v $(pwd):/srv --rm caddydz/hamz-a.github.io
```
> Port 35729 is bound for live reload
5. Open http://localhost:4000 in a browser