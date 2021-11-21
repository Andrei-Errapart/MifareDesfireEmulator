open System.Collections.Generic
open System.IO
open System.Linq
open System.Net
open System.Net.Sockets
open System.Reflection
open System.Runtime.Serialization.Json
open System.Security.Cryptography
open System.Text
open System.Threading
open System.Xml

open MDComm

// Done:
// 1. Authenticate with all zeroes.
// TODO:
// 1. Implement all commands (using libfreefare as a client).
// 2. Implement file encryption/decryption.
// 3. Implement 3DES.

// ======================================================================
/// Object to Json 
let internal json<'t> (myObj:'t) =   
        use ms = new MemoryStream() 
        (new DataContractJsonSerializer(typeof<'t>)).WriteObject(ms, myObj) 
        Encoding.Default.GetString(ms.ToArray()) 

// ======================================================================
/// Object from Json 
let internal unjson<'t> (jsonString:string)  : 't =  
        use ms = new MemoryStream(ASCIIEncoding.Default.GetBytes(jsonString)) 
        let obj = (new DataContractJsonSerializer(typeof<'t>)).ReadObject(ms) 
        obj :?> 't

// ======================================================================
let bytes_of_hexstring (s:string) =
    Array.init (s.Length/2) (fun i -> byte (System.Int32.Parse(s.Substring(2*i, 2), System.Globalization.NumberStyles.HexNumber)))

// ======================================================================
let hexstring_of_bytes (bytes:byte[]) =
    seq { for b in bytes do yield sprintf "%02X" b } |> String.concat ""

// ======================================================================
let uint16_of_bytes_le (src:byte[]) (offset:int) =
    ((int src.[offset+0]) <<< 0) ||| ((int src.[offset+1]) <<< 8)

// ======================================================================
let bytes_of_int24_le (i24:int) =
    [| byte (i24 >>> 0); byte (i24 >>> 8); byte (i24 >>> 16); |]

// ======================================================================
let uint24_of_bytes_le (src:byte[]) (offset:int) =
    ((int src.[offset+0]) <<< 0) ||| ((int src.[offset+1]) <<< 8) ||| ((int src.[offset+2]) <<< 16)
    

// ======================================================================
/// For active pattern matching.
let (|Equals|_|) (lhs) (rhs)  =
    if lhs = rhs then Some(lhs) else None

// ======================================================================
let rng = new System.Random()

// ======================================================================
let iso14443a_crc (data:byte[]) (offset:int) (length:int) =
    let mutable t = 0uy
    let mutable crc = 0x6363us
    for i=0 to length-1 do
        t <- (data.[offset + i] ^^^ (byte crc))
        t <- t ^^^ (t <<< 4)
        crc <- (crc >>> 8) ^^^ ((uint16 t) <<< 8) ^^^ ((uint16 t) <<< 3) ^^^ ((uint16 t) >>> 4)
    int crc

// ======================================================================
let MAX_APPLICATIONS            = 28    // Maximum number of applications.
let MAX_KEYS_PER_APPLICATION    = 14    // Maximum number of keys per application
let MAX_FILE_SIZE               = 8192  // Maximum file size.
let MAX_DATA_SIZE               = 59    // maximum number of bytes in one block of exchange.

let BLOCK_SIZE      = 8
let DES3_KEY_LENGTH = 16
let DES_KEY_LENGTH  = 8

let CARDUID_LENGTH = 7

let MKEYBIT_CHANGEABLE                      = 1
let MKEYBIT_REQUIRED_FOR_APP_LIST           = 2
let MKEYBIT_REQUIRED_FOR_APP_CREATE_DELETE  = 4
let MKEYBIT_CONFIGURATION_CHANGEABLE        = 8

let ACCESSRIGHTS_READ_OFFSET        = 12
let ACCESSRIGHTS_WRITE_OFFSET       = 8
let ACCESSRIGHTS_READWRITE_OFFSET   = 4
let ACCESSRIGHTS_CHANGE_OFFSET      = 0
let ACCESSRIGHTS_MASK               = 0x0F

let KEYID_FREE_ACCESS               = 0x0E
let KEYID_DENY_ACCESS               = 0x0F

// -- File types.
let FILETYPE_STANDARD_DATA              = 0x00
let FILETYPE_BACKUP_DATA                = 0x01
let FILETYPE_VALUE_WITH_BACKUP          = 0x02
let FILETYPE_LINEAR_RECORD_WITH_BACKUP  = 0x03
let FILETYPE_CYCLIC_RECORD_WITH_BACKUP  = 0x04

// Parameter for CMD_SET_CONFIGURATION
let SETCONFIGURATION_CONFIGURATION  = 0x00uy
// set the default key to be used when creating new applications.
let SETCONFIGURATION_DEFAULT_KEY    = 0x01uy
let SETCONFIGURATION_ATS            = 0x02uy

// -- Security related commands.
let CMD_AUTHENTICATE                = 0x0Auy
let CMD_GET_KEYSETTINGS             = 0x45uy
let CMD_CHANGE_KEY                  = 0xC4uy
let CMD_GET_KEYVERSION              = 0x64uy
let CMD_SET_CONFIGURATION           = 0x5Cuy
// configures the card and pre-personalizes the card with a key, defines if the UID or the random ID is sent back during communication setup and configures the ATS string
// http://www.gorferay.com/mifare-desfire-ev1-command-set/

// -- PICC level commands.
let CMD_CREATE_APPLICATION          = 0xCAuy
let CMD_DELETE_APPLICATION          = 0xDAuy
let CMD_GET_APPLICATION_IDS         = 0x6Auy
let CMD_SELECT_APPLICATION          = 0x5Auy
let CMD_FORMAT_PICC                 = 0xFCuy
let CMD_GET_VERSION                 = 0x60uy
let CMD_FREEMEMORY                  = 0x6Euy

// -- APPLICATION LEVEL COMMANDS
let CMD_GET_FILE_SETTINGS           = 0xF5uy
let CMD_CHANGE_FILE_SETTINGS        = 0x5Fuy
let CMD_CREATE_STD_DATA_FILE        = 0xCDuy
let CMD_DELETE_FILE                 = 0xDFuy

// -- DATA MANIPULATION COMMANDS
let CMD_READ_DATA                   = 0xBDuy
let CMD_WRITE_DATA                  = 0x3Duy

// -- Miscellaneous commands.
let CMD_ADDITIONAL_FRAME            = 0xAFuy

let STATUS_OPERATION_OK             = 0x00uy
let STATUS_NO_CHANGES               = 0x0Cuy
let STATUS_OUT_OF_EEPROM_ERROR      = 0x0Euy
let STATUS_ILLEGAL_COMMAND_CODE     = 0x1Cuy
let STATUS_INTEGRITY_ERROR          = 0x1Euy
let STATUS_NO_SUCH_KEY              = 0x40uy
let STATUS_LENGTH_ERROR             = 0x7Euy
let STATUS_PERMISSION_DENIED        = 0x9Duy
let STATUS_PARAMETER_ERROR          = 0x9Euy
let STATUS_APPLICATION_NOT_FOUND    = 0xA0uy
let STATUS_APPL_INTEGRITY_ERROR     = 0xA1uy
let STATUS_AUTHENTICATION_ERROR     = 0xAEuy
let STATUS_ADDITIONAL_FRAME         = 0xAFuy
let STATUS_BOUNDARY_ERROR           = 0xBEuy
let STATUS_PICC_INTEGRITY_ERROR     = 0xC1uy
let STATUS_COMMAND_ABORTED          = 0xCAuy
let STATUS_PICC_DISABLED_ERROR      = 0xCDuy
let STATUS_COUNT_ERROR              = 0xCEuy
let STATUS_DUPLICATE_ERROR          = 0xDEuy
let STATUS_EEPROM_ERROR             = 0xEEuy
let STATUS_FILE_NOT_FOUND           = 0xF0uy
let STATUS_FILE_INTEGRITY_ERROR     = 0xF1uy

// ======================================================================
let create_3des_encryptor_decryptor (key:byte[]) =
    let des = new System.Security.Cryptography.TripleDESCryptoServiceProvider()
    des.BlockSize <- BLOCK_SIZE * 8
    des.Mode <- CipherMode.ECB
    des.Padding <- PaddingMode.None
    // By default, the Desfire uses weak key (all zeroes).
    // Thus, the bypass of the check done by CreateEncryptor.
    let iv = Array.zeroCreate<byte> BLOCK_SIZE
    let mi = des.GetType().GetMethod("_NewEncryptor", (BindingFlags.NonPublic ||| BindingFlags.Instance))
    let invoke (x:int) = mi.Invoke(des, [| key :> obj; des.Mode :> obj; iv :> obj; des.FeedbackSize :> obj; x :> obj|]) :?> ICryptoTransform
    invoke 0, invoke 1

// ======================================================================
let create_3des_block_encryptor_decryptor (key:byte[]) =
    let encoder, decoder = create_3des_encryptor_decryptor key
    (fun (b:byte[]) -> encoder.TransformFinalBlock(b, 0, BLOCK_SIZE)), (fun (b:byte[]) -> decoder.TransformFinalBlock(b, 0, BLOCK_SIZE))

// ======================================================================
let unwrap_apdu (apdu:byte[]) =
    if apdu.Length>=5 then
        let expected_length = if apdu.Length>5 then (int(apdu.[4])) + 6 else 5
        if apdu.[0]=0x90uy && apdu.[2]=0uy && apdu.[3]=0uy && apdu.Last()=0uy then
            if apdu.Length=5 then
                apdu.[1], [| |]
            else if apdu.Length=expected_length then
                apdu.[1], apdu.[5 .. 5 + (int (apdu.[4])) - 1 ]
            else
                failwith "unwrap_apdu: Invalid length."
        else
            failwith "unwrap_apdu: Invalid signature."
    else
        failwith "unwrap_apdu: Too short query."

// ======================================================================
// Shift block by offset to the left.
let block_left (offset:int) (b:byte[]) =
    let length = b.Length
    Array.init length (fun i -> b.[(i + length + offset) % length])

// ======================================================================
let block_xor (b1:byte[]) (b2:byte[]) =
    let length = b1.Length
    Array.init length (fun i -> b1.[i] ^^^ b2.[i])

// ======================================================================
let wrap_response (res:byte[]) (status:byte) =
    Array.init (res.Length + 2) (fun i -> if i=res.Length then 0x91uy else if i=res.Length+1 then status else res.[i])

// ======================================================================
let block_eq (b1:byte[]) (b2:byte[]) =
    let length = b1.Length
    let mutable eq = true
    for i=0 to length-1 do
        eq <- eq && b1.[i]=b2.[i]
    eq

// ======================================================================
// Single-DES: first half equals to second half.
// 3DES: different halves.
let is_3des_key (key:byte[]) =
    let n2 = key.Length/2
    let mutable eq = true
    for i=0 to n2-1 do
        eq <- eq && key.[i]=key.[n2+i]
    not eq

// ======================================================================
(*
let _write_fixdelimited (s:Stream) (msg:MDComm.MessageFromSlave) =
    let len = msg.SerializedSize
    s.Write( [| byte (len >>> 0); byte (len >>> 8); byte (len >>> 16); byte (len >>> 24) |], 0, 4) 
    msg.WriteTo(s)
*)

// ======================================================================
(*
let _read_fixdelimited (s:Stream) =
    let buf1 = Array.zeroCreate<byte> 4
    let buf1_read = s.Read(buf1, 0, buf1.Length)
    if buf1_read<>buf1.Length then
        failwith "_read_fixdelimited: EOF while reading."
    let len = ((int32 buf1.[0]) <<< 0) ||| ((int32 buf1.[1]) <<< 8) ||| ((int32 buf1.[2]) <<< 16) ||| ((int32 buf1.[3]) <<< 24)
    let buf2 = Array.zeroCreate<byte> len
    let buf2_read = s.Read(buf2, 0, buf2.Length)
    if buf2_read<>buf2.Length then
        failwith "_read_fixdelimited: EOF while reading."
    let s2 = new System.IO.MemoryStream(buf2)
    MDComm.MessageToSlave.ParseFrom(s2)
*)

// ======================================================================
type AuthResult() =
    member val KeyId = 0 with get, set
    member val SessionKey = Array.zeroCreate<byte> DES3_KEY_LENGTH with get, set
    member val IV = Array.zeroCreate<byte> BLOCK_SIZE with get, set
    member val Encoder = null :> ICryptoTransform with get, set
    member val Decoder = null :> ICryptoTransform with get, set
    (* The PICC always ENCRYPTS. Thus, the encryption and decryption differ by whenever the XOR with IV is done either before or after the encryption procedure.
    *)
    /// Encrypt one BLOCK_SIZE
    member this.BlockEncrypt (b:byte[]) (offset:int) =
        let x = this.Encoder.TransformFinalBlock(block_xor this.IV b.[offset .. offset+BLOCK_SIZE-1], 0, BLOCK_SIZE)
        this.IV <- x.[0 .. BLOCK_SIZE-1]
        x
    /// Decrypt one BLOCK_SIZE
    member this.BlockDecrypt (b:byte[]) (offset:int) =
        let x = this.Encoder.TransformFinalBlock(b, offset, BLOCK_SIZE) |> block_xor this.IV
        this.IV <- b.[offset .. offset+BLOCK_SIZE-1]
        x
    /// Encrypt multiple blocks.
    member this.BufferEncrypt (b:byte[]) =
        let nrounds = b.Length / BLOCK_SIZE
        let r = seq { for i=0 to nrounds-1 do yield this.BlockEncrypt b (i*BLOCK_SIZE) } |> Array.concat
        r
    /// Decrypt multiple blocks.
    member this.BufferDecrypt (b:byte[]) =
        let nrounds = b.Length / BLOCK_SIZE
        let r = seq { for i=0 to nrounds-1 do yield this.BlockDecrypt b (i*BLOCK_SIZE) } |> Array.concat
        r

// ======================================================================
type Key() =
    member val Version = 0 with get, set
    member val Des3Key = Array.zeroCreate<byte> DES3_KEY_LENGTH with get, set
    member this.Duplicate() =
        new Key(Version=this.Version, Des3Key=this.Des3Key.[0 .. this.Des3Key.Length-1])

type File() =
    member val FileType = FILETYPE_STANDARD_DATA with get, set
    member val CommunicationSettings = 0x00 with get, set
    member val AccessRights = 0x00 with get, set
    member val Contents = Array.zeroCreate<byte> 0 with get, set

type Application() =
    member val MasterKeyConfiguration = 0x0F with get, set
    member val Files = new Dictionary<int, File>() with get, set
    member val Keys = Array.init 1 (fun _ -> new Key()) with get, set
    /// Is this key id within limits?
    member this.IsKeyIdValid (key_id:int) =
        key_id=KEYID_FREE_ACCESS || key_id=KEYID_DENY_ACCESS || (key_id>=0 && key_id<this.Keys.Length)
    /// Is this access rights within limits?
    member this.IsAccessRightsValid (access_rights:int) =
        let key_id_read = (access_rights >>> ACCESSRIGHTS_READ_OFFSET) &&& 0x0F
        let key_id_write = (access_rights >>> ACCESSRIGHTS_WRITE_OFFSET) &&& 0x0F
        let key_id_readwrite = (access_rights >>> ACCESSRIGHTS_READWRITE_OFFSET) &&& 0x0F
        let key_id_change = (access_rights >>> ACCESSRIGHTS_CHANGE_OFFSET) &&& 0x0F
        let r = (this.IsKeyIdValid key_id_read) && (this.IsKeyIdValid key_id_write) && (this.IsKeyIdValid key_id_readwrite) && (this.IsKeyIdValid key_id_change)
        r

    member private this._CheckMasterIfZero (bitmask:int, sess:AuthResult option) =
        if (this.MasterKeyConfiguration &&& bitmask) = 0 then
            match sess with
            | Some ar -> ar.KeyId=0
            | None -> false
        else
            true

    /// App. master key: Is master key changeable?
    member this.IsMasterKeyChangePermitted (sess:AuthResult option) =
        this._CheckMasterIfZero (0x01, sess)
    /// App. master key: Is directory access (GetFileIDs, GetFileSettings, GetKeySettings) permitted?
    member this.IsDirectoryAccessPermitted (sess:AuthResult option) =
        this._CheckMasterIfZero(0x02, sess)
    /// App. master key: Is CreateFile/DeleteFile permitted?
    member this.IsCreateDeleteFilePermitted (sess:AuthResult option) =
        this._CheckMasterIfZero (0x04, sess)
    /// App. master key: Can the configuration be changed?
    member this.IsConfigurationChangePermitted (sess:AuthResult option) =
        this._CheckMasterIfZero (0x08, sess)
    member this.IsKeyChangePermitted (key_id_to_be_changed:int, sess:AuthResult option) =
        let x = this.MasterKeyConfiguration >>> 4
        if x=0x0F then
            this.IsMasterKeyChangePermitted(sess)
        else if x=0x0E then
            match sess with
            | Some ar -> ar.KeyId = key_id_to_be_changed
            | None -> false
        else if x=0x00 then
            match sess with
            | Some ar -> ar.KeyId = 0
            | None -> false
        else
            match sess with
            | Some ar -> ar.KeyId = x
            | None -> false

type Card() =
    member val Id = Array.zeroCreate<byte> CARDUID_LENGTH with get, set
    member val MasterKeyConfiguration = 0x0F with get, set
    member val MasterKey = new Key() with get, set
    member val Applications = new Dictionary<int, Application>() with get, set

    member this.IsMasterKeyConfigurationFrozen = (this.MasterKeyConfiguration &&& 0x08) = 0
    member this.IsApplicationProtected = (this.MasterKeyConfiguration &&& 0x04) = 0
    member this.IsApplicationDirectoryProtected = (this.MasterKeyConfiguration &&& 0x02) = 0
    member this.IsMasterKeyFrozen = (this.MasterKeyConfiguration &&& 0x01) = 0

// ======================================================================
type CommunicationMode =
| PlainCommunication
| EncryptedCommunication

type TransceiveMode = 
| Normal
| Continuation

// ======================================================================
type MifareDesfire(client_name:string, card:Card) =
    let encoder, decoder = create_3des_encryptor_decryptor card.MasterKey.Des3Key
    member val private ApplicationId = 0 with get, set
    member val private Session : AuthResult option = None with get, set
    member val private Mode = TransceiveMode.Normal with get, set
    member val private LastCmd = 0uy with get, set
    member val private VersionResponse:byte[][] = [|
                                                [| 0x04uy; 0x01uy; 0x01uy; 0x01uy; 0x00uy; 0x1Auy; 0x05uy; |];
                                                [| 0x04uy; 0x01uy; 0x01uy; 0x01uy; 0x04uy; 0x1Auy; 0x05uy; |];
                                                [| card.Id.[0];  card.Id.[1]; card.Id.[2];card.Id.[3];card.Id.[4];card.Id.[5]; card.Id.[6]; 0xBAuy; 0x34uy; 0x17uy; 0x99uy; 0x50uy; |]
                                          |]
    member val private VersionResponseIndex = 0 with get, set
    /// file_no * offset * length * todo * buffer * comm_mode
    member val private ContinuedWriteData : (int * int * int * int * List<byte> * CommunicationMode) option = None with get, set
    /// buffer * so_far
    member val private ContinuedReadData : (byte[] * int) option = None with get, set
    // key_no, key, RndB, encoder, decoder
    member val private ContinuedAuth : (int * byte[] * byte[] * (byte[] -> byte[]) * (byte[] -> byte[])) option = None with get, set
    member val private DefaultKey = new Key() with get, set

    member private this.EndWriteData (client_name:string) (file:File) (offset:int) (length:int) (buffer:List<byte>) (comm_mode:CommunicationMode) =
        let ok, data = 
            match comm_mode with
            | PlainCommunication -> true, buffer.ToArray()
            | EncryptedCommunication ->
                let bdata = buffer.ToArray()
                match this.Session with
                | Some session ->
                    let r1 = session.BufferDecrypt(bdata)
                    (*
                    let r2 = session.BufferEncrypt(bdata)
                    printfn "r1 = %s" (hexstring_of_bytes r1)
                    printfn "r2 = %s" (hexstring_of_bytes r1)
                    *)
                    let crc_new = iso14443a_crc r1 0 length
                    let crc_old = uint16_of_bytes_le r1 length
                    printfn "%s: crc_new=0x%04X, crc_old=0x%04X" client_name crc_new crc_old
                    crc_new=crc_old, r1
                | None ->
                    printfn "%s: Internal error 1" client_name
                    false, [| |]
        // Copy the data over, too.
        if ok then
            for i=0 to length-1 do
                file.Contents.[offset + i] <- data.[i]
        if ok then STATUS_OPERATION_OK else STATUS_INTEGRITY_ERROR

    /// Decode the new key, if the CRC happens to match.
    member private this._DecodeKey (key_no:int, encrypted_key:byte[], session:AuthResult, current_key:byte[]) =
        let key_data = session.BufferDecrypt(encrypted_key)
        let crc_new = iso14443a_crc key_data 0 DES3_KEY_LENGTH
        let crc_old = uint16_of_bytes_le key_data DES3_KEY_LENGTH
        if crc_new=crc_old then
            if key_no = session.KeyId then
                // short version
                true, key_data.[0..DES3_KEY_LENGTH-1], "OK!"
            else
                let new_key = block_xor (key_data.[0..DES3_KEY_LENGTH-1]) current_key
                let crc_key = uint16_of_bytes_le key_data (DES3_KEY_LENGTH+2)
                let crc_new_key = iso14443a_crc new_key 0 (new_key.Length)
                if crc_key = crc_new_key then
                    true, new_key, "OK!"
                else
                    false, [| |], (sprintf "CRC mismatch: new=0x%04X, old=0x%04X" crc_new_key crc_key)
        else
            false, [| |], (sprintf "CRC mismatch: new=0x%04X, old=0x%04X" crc_new crc_old)

    // Here is where the action happens :)
    member this.Transceive (apdu:byte[]) (response_length:uint32) = 
        printfn "%s: query %s, response_length:%u" client_name (hexstring_of_bytes apdu) response_length
        let cmd, args = unwrap_apdu apdu
        if cmd<>CMD_ADDITIONAL_FRAME then
            this.Mode <- TransceiveMode.Normal
            this.LastCmd <- cmd
        let status, response =
            match this.Mode with
            | Normal ->
                (
                match cmd with
                | Equals CMD_AUTHENTICATE _ ->
                    if args.Length=1 then
                        let rnd_b = Array.init BLOCK_SIZE (fun _ -> byte (rng.Next(0, 256)))
                        printfn "%s: Authenticate: RndB=%s" client_name (hexstring_of_bytes rnd_b)
                        this.Session <- None
                        let key_no = int args.[0]
                        let continue_with_key (key:byte[]) =
                            printfn "%s: AuthKey=%s" client_name (hexstring_of_bytes key) 
                            let encoder, decoder = create_3des_block_encryptor_decryptor key
                            this.ContinuedAuth <- Some (key_no, key, rnd_b, encoder, decoder)
                            STATUS_ADDITIONAL_FRAME, encoder rnd_b
                        if this.ApplicationId=0 then
                            if key_no=0 then
                                continue_with_key card.MasterKey.Des3Key
                            else
                                printfn "%s: Only master key present at the PICC level." client_name
                                STATUS_NO_SUCH_KEY, [| |]
                        else
                            let app = card.Applications.[this.ApplicationId]
                            if key_no>=0 && key_no<app.Keys.Length then
                                continue_with_key app.Keys.[key_no].Des3Key
                            else
                                printfn "%s: Given key not found in app 0x%06X." client_name this.ApplicationId
                                STATUS_NO_SUCH_KEY, [| |]
                    else
                        printfn "%s: Authenticate: Command length error." client_name
                        STATUS_LENGTH_ERROR, [| |]
                | Equals CMD_GET_KEYSETTINGS _ ->
                    printfn "%s: Get KeySettings" client_name
                    if this.ApplicationId=0 then
                        let ok = card.IsApplicationDirectoryProtected || (match this.Session with | Some ar -> true | None -> false)
                        if ok then
                            STATUS_OPERATION_OK, [| byte card.MasterKeyConfiguration; 0x01uy |]
                        else
                            printfn "%s: Get KeySettings: Permission denied with this key (if any)." client_name
                            STATUS_PERMISSION_DENIED, [| |]
                    else
                        let app = card.Applications.[this.ApplicationId]
                        if app.IsDirectoryAccessPermitted(this.Session) then
                            STATUS_OPERATION_OK, [| byte app.MasterKeyConfiguration; byte app.Keys.Length |]
                        else
                            printfn "%s: Get KeySettings: Permission denied with this key (if any)." client_name
                            STATUS_PERMISSION_DENIED, [| |]
                | Equals CMD_CHANGE_KEY _ ->
                    if args.Length = 25 then
                        let key_no = int (args.[0])
                        let encrypted_key = args.[1..]
                        match this.Session with
                        | Some ar ->
                            if this.ApplicationId=0 then
                                // master key change.
                                if key_no=0 then
                                    if card.IsMasterKeyFrozen then
                                        printfn "%s: ChangeKey: Card master key is already frozen!" client_name
                                        STATUS_PERMISSION_DENIED, [| |]
                                    else
                                        // ok, how to change?
                                        match this._DecodeKey(key_no, encrypted_key, ar, card.MasterKey.Des3Key) with
                                        | false, _, msg ->
                                            printfn "%s: ChangeKey: Error %s" client_name msg
                                            STATUS_PARAMETER_ERROR, [| |]
                                        | true, new_key, _ ->
                                            printfn "%s: ChangeKey: Decrypted key: %A" client_name (hexstring_of_bytes new_key)
                                            card.MasterKey.Des3Key <- new_key
                                            this.Session <- None
                                            STATUS_OPERATION_OK, [| |]
                                else
                                    printfn "%s: Change Key: Card master key change must be done with KeyId of 0." client_name
                                    STATUS_PARAMETER_ERROR, [| |]
                            else
                                let app = card.Applications.[this.ApplicationId]
                                if app.IsKeyChangePermitted(key_no, this.Session) then
                                    // ok, how to change?
                                    let old_key = app.Keys.[ar.KeyId].Des3Key
                                    match this._DecodeKey(key_no, encrypted_key, ar, old_key) with
                                    | false, _, msg ->
                                        printfn "%s: ChangeKey: Error %s" client_name msg
                                        STATUS_PARAMETER_ERROR, [| |]
                                    | true, new_key, _ ->
                                        printfn "%s: ChangeKey: Application %d Decrypted key: %A" client_name (this.ApplicationId) (hexstring_of_bytes new_key)
                                        app.Keys.[key_no].Des3Key <- new_key
                                        // this.ApplicationId <- 0
                                        this.Session <- None
                                        STATUS_OPERATION_OK, [| |]
                                else
                                    printfn "%s: ChangeKey: Incorrect key (%d) specified for change key!" client_name key_no
                                    STATUS_PERMISSION_DENIED, [| |]
                        | None ->
                            printfn "%s: ChangeKey: Auth must have been done before change key!" client_name
                            STATUS_PERMISSION_DENIED, [| |]
                    else
                        printfn "%s: ChangeKey: Command length error." client_name
                        STATUS_LENGTH_ERROR, [| |]
                | Equals CMD_GET_KEYVERSION _ ->
                    if args.Length=1 then
                        let key_id = int args.[0]
                        if this.ApplicationId=0 then
                            if key_id=0 then STATUS_OPERATION_OK, [| byte card.MasterKey.Version |] else STATUS_PARAMETER_ERROR, [| |]
                        else
                            let app = card.Applications.[this.ApplicationId]
                            if key_id>=0 && key_id<app.Keys.Length then
                                STATUS_OPERATION_OK, [| byte app.Keys.[key_id].Version |]
                            else
                                printfn "%s: Get KeyVersion: key_id=%d is out of range." client_name key_id
                                STATUS_COMMAND_ABORTED, [| |]
                    else
                        printfn "%s: Get Key Version: Command length error." client_name
                        STATUS_LENGTH_ERROR, [| |]
                | Equals CMD_SET_CONFIGURATION _->
                    if args.Length>=1 then
                        printfn "%s: Args[%d] = %s" client_name args.Length (hexstring_of_bytes args)
                        if args.[0] = SETCONFIGURATION_CONFIGURATION then
                            printfn "%s: Set Configuration not implemented." client_name
                            STATUS_PARAMETER_ERROR, [| |]
                        elif args.[0] = SETCONFIGURATION_DEFAULT_KEY then
                            if args.Length=33 then
                                match this.Session with
                                | Some session ->
                                    let xkey = session.BufferDecrypt args.[1..32]
                                    printfn "%s: Decrypted: %s" client_name (hexstring_of_bytes xkey)
                                    session.IV <- Array.zeroCreate<byte> BLOCK_SIZE
                                    let crc_new = iso14443a_crc xkey 0 25
                                    let crc_old = uint16_of_bytes_le xkey 25
                                    if crc_new=crc_old then
                                        let new_key = xkey.[0..15]
                                        let new_version = int xkey.[24]
                                        printfn "%s: New Default key=%s, version=0x%02X" client_name (hexstring_of_bytes new_key) new_version
                                        this.DefaultKey <- new Key(Version=new_version, Des3Key=new_key)
                                        STATUS_OPERATION_OK, [| |]
                                    else
                                        STATUS_INTEGRITY_ERROR, [| |]
                                | None ->
                                    STATUS_PERMISSION_DENIED, [| |]
                            else
                                printfn "%s: Set Configuration: Command length error." client_name
                                STATUS_LENGTH_ERROR, [| |]
                        else
                            printfn "%s: Set Configuration: Invalid arguments: %s." client_name (hexstring_of_bytes args)
                            STATUS_PARAMETER_ERROR, [| |]
                    else
                        printfn "%s: Set Configuration: Command length error." client_name
                        STATUS_LENGTH_ERROR, [| |]
                | Equals CMD_CREATE_APPLICATION _ ->
                    if args.Length=5 then
                        let aid = uint24_of_bytes_le args 0
                        let key_settings = int (args.[3])
                        let number_of_keys = int (args.[4])
                        printfn "%s: Create Application: AID=%06X, MasterKeyConfiguration=0x%02X NumberOfKeys=%d" client_name aid key_settings number_of_keys
                        if aid=0 then
                            printfn "%s: Cannot create application with zero AID." client_name
                            STATUS_DUPLICATE_ERROR, [| |]
                        elif card.Applications.ContainsKey aid then
                            printfn "%s: Application already exists." client_name
                            STATUS_DUPLICATE_ERROR, [| |]
                        else
                            if card.Applications.Count<MAX_APPLICATIONS then
                                if number_of_keys>=1 && number_of_keys<=MAX_KEYS_PER_APPLICATION then
                                    // YEE
                                    let app = new Application(MasterKeyConfiguration=key_settings, Keys=Array.init number_of_keys (fun i -> if i=0 then this.DefaultKey.Duplicate() else new Key()))
                                    card.Applications.Add(aid, app)
                                    STATUS_OPERATION_OK, [| |]
                                else
                                    printfn "%s: Create Application: Too many keys." client_name
                                    STATUS_COUNT_ERROR, [| |]
                            else
                                printfn "%s: Create Application: Maximum number of applications exceeded." client_name
                                STATUS_COUNT_ERROR, [| |]
                    else
                        printfn "%s: Create Application: Length error." client_name
                        STATUS_LENGTH_ERROR, [| |]
                | Equals CMD_DELETE_APPLICATION _ ->
                    if args.Length=3 then
                        let aid = uint24_of_bytes_le args 0
                        let picc_master = this.ApplicationId=0 && (match this.Session with | Some _ -> true | None -> false)
                        let remove_app () =
                            if card.Applications.ContainsKey aid then
                                card.Applications.Remove(aid) |> ignore
                                printfn "%s: Deleted application %d." client_name aid
                                STATUS_OPERATION_OK, [| |]
                            else
                                printfn "%s: Delete application: No such application: %d!" client_name aid
                                STATUS_APPLICATION_NOT_FOUND, [| |]
                        if card.IsApplicationProtected then
                            // only PICC master key is accepted
                            if picc_master then
                                remove_app ()
                            else
                                printfn "%s: Delete Application: Have to authenticate with the PICC master key first!" client_name
                                STATUS_PERMISSION_DENIED, [| |]
                        else
                            // either PICC master key or application master key is required.
                            let app_master = this.ApplicationId>0 && (match this.Session with | Some ar -> ar.KeyId=0 | None -> false)
                            if picc_master || app_master then
                                remove_app ()
                            else
                                printfn "%s: Delete Application: Have to authenticate with the PICC or Application master key first!" client_name
                                STATUS_PERMISSION_DENIED, [| |]
                    else
                        printfn "%s: Delete Application: Length error." client_name
                        STATUS_LENGTH_ERROR, [| |]
                | Equals CMD_GET_APPLICATION_IDS _ ->
                    let ok = (not card.IsApplicationDirectoryProtected) || (this.ApplicationId=0 && (match this.Session with | Some _ -> true | None -> false) )
                    if ok then
                        let r = new List<byte>()
                        r.AddRange(bytes_of_int24_le 0)
                        for kv in card.Applications do
                            r.AddRange(bytes_of_int24_le kv.Key)
                        STATUS_ADDITIONAL_FRAME, r.ToArray()
                    else
                        printfn "%s: GetApplicationIds: Have to authenticate with the PICC master key first!" client_name
                        STATUS_PERMISSION_DENIED, [| |]
                | Equals CMD_SELECT_APPLICATION _ ->
                    if args.Length=3 then
                        this.Session <- None
                        let app_id = uint24_of_bytes_le args 0
                        printfn "%s: Select application: AID=0x%06X." client_name app_id
                        if app_id=0 || card.Applications.ContainsKey(app_id) then
                            this.ApplicationId <- app_id
                            STATUS_OPERATION_OK, [| |]
                        else
                            printfn "%s: Application 0x%06X not found." client_name app_id
                            STATUS_APPLICATION_NOT_FOUND, [| |]
                    else
                        printfn "%s: Select application: Command length error." client_name
                        STATUS_LENGTH_ERROR, [| |]
                | Equals CMD_FORMAT_PICC _ ->
                    printfn "%s: Format PICC." client_name
                    if this.ApplicationId=0 && this.Session.IsSome then
                        card.MasterKeyConfiguration <- 0x0F
                        card.MasterKey <- new Key()
                        card.Applications.Clear()
                        STATUS_OPERATION_OK, [| |]
                    else
                        printfn "%s: Have to authenticate with master key first!" client_name
                        STATUS_PERMISSION_DENIED, [| |]
                | Equals CMD_GET_VERSION _ ->
                    this.VersionResponseIndex <- 0
                    STATUS_ADDITIONAL_FRAME, this.VersionResponse.[0]
                | Equals CMD_FREEMEMORY _ ->
                    STATUS_OPERATION_OK, [| 0x00uy; 0x20uy; 0x00uy; 0x00uy |]
                | Equals CMD_GET_FILE_SETTINGS _ ->
                    if args.Length=1 then
                        let file_id = int args.[0]
                        printfn "%s: Get File Settings: File=%d." client_name file_id
                        if this.ApplicationId>0 then
                            let app = card.Applications.[this.ApplicationId]
                            if app.Files.ContainsKey file_id then
                                if app.IsDirectoryAccessPermitted(this.Session) then
                                    let file = app.Files.[file_id]
                                    STATUS_OPERATION_OK, Array.concat [ [| byte file.FileType; byte file.CommunicationSettings; byte file.AccessRights |]; bytes_of_int24_le file.Contents.Length ]
                                else
                                    printfn "%s: Have to authenticate with master key first!" client_name
                                    STATUS_PERMISSION_DENIED, [| |]
                            else
                                printfn "%s: Error: File not found!" client_name
                                STATUS_FILE_NOT_FOUND, [| |]
                        else
                            printfn "%s: Error: Application not selected (yet)!" client_name
                            STATUS_PERMISSION_DENIED, [| |]
                    else
                        printfn "%s: Get File Settings: Command length error." client_name
                        STATUS_LENGTH_ERROR, [| |]
                | Equals CMD_CHANGE_FILE_SETTINGS _ ->
                    printfn "%s: ChangeFileSettings: %s" client_name (hexstring_of_bytes args)
                    STATUS_LENGTH_ERROR, [| |]
                | Equals CMD_CREATE_STD_DATA_FILE _ ->
                    if args.Length=7 then
                        let file_no = int (args.[0])
                        let communication_settings = int (args.[1])
                        let access_rights = uint16_of_bytes_le args 2
                        let file_size = uint24_of_bytes_le args 4
                        printfn "%s: App: 0x%06X: Create StdDataFile: File=%d, CommSettings=0x%02X, AccessRights=0x%04X, FileSize=%d" client_name this.ApplicationId file_no communication_settings access_rights file_size
                        if this.ApplicationId>0 then
                            let app = card.Applications.[this.ApplicationId]
                            // Does the file exist?
                            if app.Files.ContainsKey file_no then
                                printfn "%s: File=%d already exists." client_name file_no
                                STATUS_PARAMETER_ERROR, [| |]
                            else
                                if file_size>0 && file_size<MAX_FILE_SIZE then
                                    // check the keys...
                                    if app.IsAccessRightsValid access_rights then
                                        // check the permission to create file
                                        if app.IsCreateDeleteFilePermitted (this.Session) then
                                            let file = new File(FileType = FILETYPE_STANDARD_DATA, CommunicationSettings=communication_settings, AccessRights=access_rights, Contents = Array.zeroCreate<byte> file_size)
                                            app.Files.Add(file_no, file)
                                            STATUS_OPERATION_OK, [| |]
                                        else
                                            printfn "%s: Create StdDataFile: Have to authenticate with application master key first!" client_name
                                            STATUS_PERMISSION_DENIED, [| |]
                                    else
                                        printfn "%s: Invalid AccessRights=0x%04X." client_name access_rights
                                        STATUS_PARAMETER_ERROR, [| |]
                                else
                                    printfn "%s: FileSize=%d is out of limits." client_name file_size
                                    STATUS_PARAMETER_ERROR, [| |]
                        else
                            printfn "%s: Create StdDataFile: Application not selected (yet)!" client_name
                            STATUS_PARAMETER_ERROR, [| |]
                    else
                        printfn "%s: Create StdDataFile: Cannot create files in master directory." client_name
                        STATUS_LENGTH_ERROR, [| |]
                | Equals CMD_DELETE_FILE _ ->
                    if args.Length = 1 then
                        let file_no = int (args.[0])
                        if this.ApplicationId>0 then
                            let app = card.Applications.[this.ApplicationId]
                            if app.Files.ContainsKey file_no then
                                let file = app.Files.[file_no]
                                // Can we delete this?
                                if app.IsCreateDeleteFilePermitted(this.Session) then
                                    app.Files.Remove(file_no) |> ignore
                                    printfn "%s: Delete File: Removed file %d" client_name file_no
                                    STATUS_OPERATION_OK, [| |]
                                else
                                    printfn "%s: Delete File: Have to authenticate with application master key first!" client_name
                                    STATUS_PERMISSION_DENIED, [| |]
                            else
                                printfn "%s: DeleteFile: File %d not found in application %d.!" client_name file_no (this.ApplicationId)
                                STATUS_FILE_NOT_FOUND, [| |]
                        else
                            printfn "%s: DeleteFile: Application not selected (yet)!" client_name
                            STATUS_PARAMETER_ERROR, [| |]
                    else
                        printfn "%s: Delete file: Invalid command length." client_name
                        STATUS_LENGTH_ERROR, [| |]
                | Equals CMD_READ_DATA _ ->
                    if args.Length=7 then
                        let file_no = int (args.[0])
                        let offset = uint24_of_bytes_le args 1
                        let length0 = uint24_of_bytes_le args 4
                        printfn "%s: ReadData File=%d Offset=%d Length=%d" client_name file_no offset length0
                        if this.ApplicationId>0 then
                            let app = card.Applications.[this.ApplicationId]
                            // File exists?
                            if app.Files.ContainsKey file_no then
                                let file = app.Files.[file_no]
                                // Write permitted?
                                let read_key = (file.AccessRights >>> ACCESSRIGHTS_READ_OFFSET) &&& ACCESSRIGHTS_MASK
                                let readwrite_key = (file.AccessRights >>> ACCESSRIGHTS_READWRITE_OFFSET) &&& ACCESSRIGHTS_MASK
                                let read_permitted, comm_mode =
                                    if read_key=KEYID_FREE_ACCESS || readwrite_key=KEYID_FREE_ACCESS then
                                        true, PlainCommunication
                                    else
                                        match this.Session with
                                        | Some session -> session.KeyId=read_key || session.KeyId=readwrite_key, if (file.CommunicationSettings &&& 0x03)=0x03 then EncryptedCommunication else PlainCommunication
                                        | None -> false, PlainCommunication
                                if read_permitted then
                                    let length = if length0=0 then file.Contents.Length - offset else length0
                                    // Offset and length OK?
                                    if offset>=0 && length>0 && offset+length<=file.Contents.Length then
                                        // Read!
                                        let buffer =
                                            match comm_mode with
                                            | PlainCommunication -> file.Contents.[offset .. offset+length-1]
                                            | EncryptedCommunication ->
                                                let buffer_length = ((length + 2 + BLOCK_SIZE-1) / BLOCK_SIZE) * BLOCK_SIZE
                                                let tbuf = Array.zeroCreate<byte> buffer_length
                                                for i=0 to length-1 do
                                                    tbuf.[i] <- file.Contents.[offset + i]
                                                let crc = iso14443a_crc tbuf 0 length
                                                tbuf.[length] <- byte crc
                                                tbuf.[length + 1] <- byte (crc >>> 8)
                                                if length + 2 < tbuf.Length && length0=0 then
                                                    tbuf.[length + 2] <- 0x80uy
                                                match this.Session with
                                                | Some session ->
                                                    session.IV <- Array.zeroCreate<byte> BLOCK_SIZE
                                                    session.BufferEncrypt tbuf
                                                | None -> failwith (sprintf "%s: Internal error 2" client_name)
                                        let this_round = MAX_DATA_SIZE |> min ((int response_length) - 2) |> min buffer.Length
                                        if this_round<buffer.Length then
                                            /// buffer * so_far
                                            this.ContinuedReadData <- Some (buffer, this_round)
                                            STATUS_ADDITIONAL_FRAME, buffer.[0 .. this_round-1]
                                        else
                                            this.ContinuedReadData <- None
                                            STATUS_OPERATION_OK, buffer
                                    else
                                        printfn "%s: Offset or length out of range." client_name
                                        STATUS_PARAMETER_ERROR, [| |]
                                else
                                    printfn "%s: Permission denied" client_name
                                    STATUS_PERMISSION_DENIED, [| |]
                            else
                                printfn "%s: File doesn't exist." client_name
                                STATUS_PARAMETER_ERROR, [| |]
                        else
                            printfn "%s: Application not selected (yet)!" client_name
                            STATUS_PARAMETER_ERROR, [| |]
                    else
                        printfn "%s: ReadData: Command length error." client_name
                        STATUS_LENGTH_ERROR, [| |]
                | Equals CMD_WRITE_DATA _ ->
                    // Writes data to Standard Data Files or Backup Data Files.
                    if args.Length>7 then
                        let file_no = int (args.[0])
                        let offset = uint24_of_bytes_le args 1
                        let length = uint24_of_bytes_le args 4
                        printfn "%s: WriteData File=%d Offset=%d Length=%d" client_name file_no offset length
                        // App exists?
                        if this.ApplicationId>0 then
                            let app = card.Applications.[this.ApplicationId]
                            // File exists?
                            if app.Files.ContainsKey file_no then
                                let file = app.Files.[file_no]
                                // Write permitted?
                                let write_key = (file.AccessRights >>> ACCESSRIGHTS_WRITE_OFFSET) &&& ACCESSRIGHTS_MASK
                                let readwrite_key = (file.AccessRights >>> ACCESSRIGHTS_READWRITE_OFFSET) &&& ACCESSRIGHTS_MASK
                                let write_permitted, comm_mode =
                                    if write_key=KEYID_FREE_ACCESS || readwrite_key=KEYID_FREE_ACCESS then
                                        true, PlainCommunication
                                    else
                                        match this.Session with
                                        | Some session -> session.KeyId=write_key || session.KeyId=readwrite_key, if (file.CommunicationSettings &&& 0x03)=0x03 then EncryptedCommunication else PlainCommunication
                                        | None -> false, PlainCommunication
                                if write_permitted then
                                    // Offset and length OK?
                                    if offset>=0 && length>0 && offset+length<=file.Contents.Length then
                                        let buffer = new List<byte>()
                                        let todo = 
                                            match comm_mode with
                                            | PlainCommunication -> length
                                            | EncryptedCommunication -> ((length + 2 + BLOCK_SIZE-1) / BLOCK_SIZE) * BLOCK_SIZE
                                        // Write!
                                        let this_round = args.Length - 7
                                        for i=0 to this_round-1 do
                                            buffer.Add(args.[7 + i])
                                        if todo>this_round then
                                            this.ContinuedWriteData <- Some (file_no, offset, length, todo-this_round, buffer, comm_mode)
                                            STATUS_ADDITIONAL_FRAME, [| |]
                                        else
                                            this.ContinuedWriteData <- None
                                            let status = this.EndWriteData client_name file offset length buffer comm_mode
                                            status, [| |]
                                    else
                                        printfn "%s: Offset or length out of range." client_name
                                        STATUS_PARAMETER_ERROR, [| |]
                                else
                                    printfn "%s: Permission denied." client_name
                                    STATUS_PERMISSION_DENIED, [| |]
                            else
                                printfn "%s: File doesn't exist." client_name
                                STATUS_PARAMETER_ERROR, [| |]
                        else
                            printfn "%s: Application not selected (yet)!" client_name
                            STATUS_PARAMETER_ERROR, [| |]
                    else
                        printfn "%s: WriteData: Command length error." client_name
                        STATUS_LENGTH_ERROR, [| |]
                | x ->
                    printfn "%s: Unknown command: %02X" client_name x
                    STATUS_ILLEGAL_COMMAND_CODE, [| |]
                )
            | Continuation ->
                (
                if cmd=CMD_ADDITIONAL_FRAME then
                    match this.LastCmd with
                    | Equals CMD_AUTHENTICATE _ ->
                        if args.Length=2*BLOCK_SIZE then
                            match this.ContinuedAuth with
                            | Some (key_no, key, rnd_b, block_encode, block_decode) ->
                                // 1. Check RndB
                                let rnd_a = block_encode args
                                printfn "%s: RndA = %s" client_name (hexstring_of_bytes rnd_a)
                                let RndBd = args.[BLOCK_SIZE..2*BLOCK_SIZE-1] |> block_encode |> block_xor args.[0..BLOCK_SIZE-1] |> block_left (-1)
                                printfn "%s: RndBd = %s" client_name (hexstring_of_bytes RndBd)
                                if block_eq RndBd rnd_b then
                                    // this.Session <- ....
                                    let session_key =
                                        if is_3des_key key then
                                            [ rnd_a.[0..3]; rnd_b.[0..3]; rnd_a.[4..7]; rnd_b.[4..7] ] |> Array.concat
                                        else
                                            [ rnd_a.[0..3]; rnd_b.[0..3]; rnd_a.[0..3]; rnd_b.[0..3] ] |> Array.concat
                                    let session_encoder, session_decoder = create_3des_encryptor_decryptor session_key
                                    this.Session <- Some (new AuthResult(KeyId=key_no, SessionKey=session_key, Encoder=session_encoder, Decoder=session_decoder))
                                    printfn "%s: Authentication OK, session_key=%s" client_name (hexstring_of_bytes session_key)
                                    STATUS_OPERATION_OK, (rnd_a |> block_left 1 |> block_encode)
                                else
                                    printfn "%s: RndB mismatch. Aborted authentication." client_name
                                    STATUS_AUTHENTICATION_ERROR, [| |]
                            | None ->
                                printfn "%s: Nothing to authenticate in the continuation mode." client_name
                                STATUS_PERMISSION_DENIED, [| |]
                        else
                            printfn "%s: Parameter error. Aborted authentication." client_name
                            this.ContinuedAuth <- None
                            STATUS_PARAMETER_ERROR, [| |]
                    | Equals CMD_GET_VERSION _ ->
                        this.VersionResponseIndex <- this.VersionResponseIndex + 1
                        let st = if this.VersionResponseIndex+1 >= this.VersionResponse.Length then STATUS_OPERATION_OK else STATUS_ADDITIONAL_FRAME
                        st, this.VersionResponse.[this.VersionResponseIndex]
                    | Equals CMD_READ_DATA _ ->
                        match this.ContinuedReadData with
                        | Some (buffer, so_far) ->
                            printfn "%s: Continued ReadData: so_far=%d" client_name so_far
                            // assume all OK.
                            let this_round = MAX_DATA_SIZE |> min ((int response_length) - 2) |> min (buffer.Length - so_far)
                            let new_so_far = so_far + this_round
                            let r = buffer.[so_far .. so_far + this_round-1]
                            if new_so_far<buffer.Length then
                                this.ContinuedReadData <- Some (buffer, new_so_far)
                                STATUS_ADDITIONAL_FRAME, r
                            else
                                this.ContinuedReadData <- None
                                STATUS_OPERATION_OK, r
                        | None ->
                            printfn "%s: Nothing to read in the continuation mode." client_name
                            STATUS_PERMISSION_DENIED, [| |]
                    | Equals CMD_WRITE_DATA _ ->
                        match this.ContinuedWriteData with
                        | Some (file_no, offset, length, todo, buffer, comm_mode) ->
                            printfn "%s: Continued WriteData: File=%d, Offset=%d, Todo=%d, ThisRound=%d" client_name file_no offset todo args.Length
                            if args.Length<=todo then
                                // assume all OK.
                                let app = card.Applications.[this.ApplicationId]
                                let file = app.Files.[file_no]
                                for i=0 to args.Length-1 do
                                    buffer.Add(args.[i])
                                let new_todo = todo - args.Length
                                if new_todo>0 then
                                    this.ContinuedWriteData <- Some (file_no, offset, length, new_todo, buffer, comm_mode)
                                    STATUS_ADDITIONAL_FRAME, [| |]
                                else
                                    this.ContinuedWriteData <- None
                                    let status = this.EndWriteData client_name file offset length buffer comm_mode
                                    status, [| |]
                            else
                                printfn "%s: Length is too long." client_name
                                STATUS_PARAMETER_ERROR, [| |]
                        | None ->
                            printfn "%s: Nothing to write in the continuation mode." client_name
                            STATUS_PERMISSION_DENIED, [| |]
                    | x ->
                        printfn "%s: Unknown command in continuation mode: %02X" client_name x
                        STATUS_ILLEGAL_COMMAND_CODE, [| |]
                else
                    printf "%s: Unexpected command: %02X. Aborting continuation." client_name cmd
                    STATUS_COMMAND_ABORTED, [| |]
                )
        printfn "%s: status:0x%02X, response [ %s ]" client_name status (hexstring_of_bytes response) 
        this.Mode <- if status=STATUS_ADDITIONAL_FRAME then TransceiveMode.Continuation else TransceiveMode.Normal
        wrap_response response status

// ======================================================================
let serve_connection (param: obj) =
    let client, card_uid = param :?> (TcpClient * (byte[]))
    let card_filename = sprintf "card-%s.txt" (hexstring_of_bytes card_uid)
    let endpoint = client.Client.RemoteEndPoint
    let client_name = (endpoint.ToString())
    let stream = client.GetStream()
    let mutable read_ok = true
    let card =
        try
            let s = System.IO.File.ReadAllText(card_filename)
            let x = unjson<Card> s
            printfn "%s: Card contents loaded from file '%s'." client_name card_filename
            x
        with
        | ex ->
            printfn "%s: Using defaults. Cannot read card file '%s'. Error: %s" client_name card_filename ex.Message
            new Card(Id = card_uid )
    let md = new MifareDesfire(client_name, card)
    try
        // 1st. message is different for the Operator.
        while client.Connected do
            let msg = MDComm.MessageToSlave.ParseDelimitedFrom stream
            if msg.HasId && msg.HasQuery && msg.HasResponseLength then
                let id, query, response_length = msg.Id, msg.Query.ToByteArray(), msg.ResponseLength
                let b = (new MDComm.MessageFromSlave.Builder()).SetId(id)
                let reply_msg =
                    try
                        let response = md.Transceive query response_length
                        b.SetResponse(Google.ProtocolBuffers.ByteString.CopyFrom(response)).Build()
                    with
                    | ex ->
                        printfn "%s: Error processing command %s: %s" client_name (hexstring_of_bytes query) ex.Message
                        b.SetMessage(ex.Message).Build()
                reply_msg.WriteDelimitedTo stream
            else
                printfn "%s: Message without Id or Query received." client_name
    with
    | ex -> printfn "%s: Error: %s" client_name ex.Message
    client.Close()
    printfn "%s:  Disconnected." client_name
    try
        let s = json<Card> card
        System.IO.File.WriteAllText(card_filename, s)
    with
    | ex -> printfn "%s: Error when storing card file: %s" client_name ex.Message
    ()

// ======================================================================
[<EntryPoint>]
let main argv = 
    let ipAddress = IPAddress.Any
    let port = 1555
    try
        let scard_uid = if argv.Length>0 then argv.[0] else "04345678123456"
        let card_uid = bytes_of_hexstring scard_uid
        if card_uid.Length=CARDUID_LENGTH then
            let listener = TcpListener(ipAddress, port)
            listener.Start()
            printfn "mdemu: Listening on port %d, serving as card %s" port (hexstring_of_bytes card_uid)
            while true do
                let client = listener.AcceptTcpClient()
                let client_name = client.Client.RemoteEndPoint.ToString()
                printfn "%s:  Connected." client_name
                let th = new Thread(new ParameterizedThreadStart(serve_connection))
                th.Start( (client, card_uid) )
                ()
        else
            printfn "Error: card uid should consist of %d hex bytes, got %s" CARDUID_LENGTH scard_uid
    with
    | ex -> printfn "Error: %s" ex.Message
    0
