namespace MDComm

open System
open System.IO
open System.Text

module private Proto =
    let readByte (stream: Stream) =
        let b = stream.ReadByte()
        if b < 0 then raise (EndOfStreamException())
        byte b

    let readVarint64 (stream: Stream) =
        let mutable shift = 0
        let mutable result = 0UL
        let mutable keepGoing = true
        while keepGoing do
            if shift >= 64 then failwith "Invalid protobuf varint."
            let b = readByte stream
            result <- result ||| ((uint64 (b &&& 0x7Fuy)) <<< shift)
            keepGoing <- (b &&& 0x80uy) <> 0uy
            shift <- shift + 7
        result

    let writeVarint64 (stream: Stream) (value: uint64) =
        let mutable v = value
        while v >= 0x80UL do
            stream.WriteByte(byte ((v &&& 0x7FUL) ||| 0x80UL))
            v <- v >>> 7
        stream.WriteByte(byte v)

    let readExactly (stream: Stream) length =
        let buffer = Array.zeroCreate<byte> length
        let mutable offset = 0
        while offset < length do
            let count = stream.Read(buffer, offset, length - offset)
            if count = 0 then raise (EndOfStreamException())
            offset <- offset + count
        buffer

    let skipField (stream: Stream) wireType =
        match wireType with
        | 0 -> readVarint64 stream |> ignore
        | 2 -> readExactly stream (int (readVarint64 stream)) |> ignore
        | _ -> failwithf "Unsupported protobuf wire type %d." wireType

    let writeBytesField (stream: Stream) fieldNumber (bytes: byte[]) =
        writeVarint64 stream (uint64 ((fieldNumber <<< 3) ||| 2))
        writeVarint64 stream (uint64 bytes.Length)
        stream.Write(bytes, 0, bytes.Length)

    let writeInt32Field (stream: Stream) fieldNumber value =
        writeVarint64 stream (uint64 (fieldNumber <<< 3))
        writeVarint64 stream (uint64 (int64 value))

    let writeUInt32Field (stream: Stream) fieldNumber value =
        writeVarint64 stream (uint64 (fieldNumber <<< 3))
        writeVarint64 stream (uint64 value)

type MessageToSlave(id: int option, query: byte[] option, responseLength: uint32 option) =
    member _.HasId = id.IsSome
    member _.Id = id.Value
    member _.HasQuery = query.IsSome
    member _.Query = query.Value
    member _.HasResponseLength = responseLength.IsSome
    member _.ResponseLength = responseLength.Value

    static member ParseFrom(stream: Stream) =
        let mutable id = None
        let mutable query = None
        let mutable responseLength = None
        while stream.Position < stream.Length do
            let key = int (Proto.readVarint64 stream)
            let fieldNumber = key >>> 3
            let wireType = key &&& 7
            match fieldNumber, wireType with
            | 1, 0 -> id <- Some(int32 (uint64 (Proto.readVarint64 stream)))
            | 2, 2 -> query <- Some(Proto.readExactly stream (int (Proto.readVarint64 stream)))
            | 3, 0 -> responseLength <- Some(uint32 (Proto.readVarint64 stream))
            | _, _ -> Proto.skipField stream wireType
        MessageToSlave(id, query, responseLength)

    static member ParseDelimitedFrom(stream: Stream) =
        let length = int (Proto.readVarint64 stream)
        use payload = new MemoryStream(Proto.readExactly stream length)
        MessageToSlave.ParseFrom(payload)

type MessageFromSlave(id: int, response: byte[] option, message: string option) =
    member _.WriteTo(stream: Stream) =
        Proto.writeInt32Field stream 1 id
        response |> Option.iter (Proto.writeBytesField stream 2)
        message
        |> Option.iter (fun text -> Proto.writeBytesField stream 3 (Encoding.UTF8.GetBytes text))

    member this.ToByteArray() =
        use stream = new MemoryStream()
        this.WriteTo(stream)
        stream.ToArray()

    member this.WriteDelimitedTo(stream: Stream) =
        let bytes = this.ToByteArray()
        Proto.writeVarint64 stream (uint64 bytes.Length)
        stream.Write(bytes, 0, bytes.Length)
        stream.Flush()
