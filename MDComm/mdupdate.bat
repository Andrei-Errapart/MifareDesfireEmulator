REM Update the protocol definitions.
rem lib\protoc.exe --java_out=src --proto_path=. mdcomm.proto
lib\protogen.exe -namespace=MDComm -umbrella_classname=MDComm --proto_path=.  mdcomm.proto

