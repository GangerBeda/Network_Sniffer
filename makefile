RUNTIME=linux-x64

all:
	dotnet build -o build

clean:
	dotnet clean
	rm -rf build