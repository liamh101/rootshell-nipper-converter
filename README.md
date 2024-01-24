## Nipper 3 to Prism

Convert a simple Nipper 3 XML file to a Prism JSON file. 

How to use

`./prismNipper3 original.xml original_prism.json`

Development Environment:

`docker build -t gonipper .`

`docker run -it -v $(pwd):/usr/local/go/src/prismNipper3 gonipper bash`

Build: 

Linux
`go build`

Windows
`env GOOS=windows GOARCH=amd64 go build`