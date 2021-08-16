#!/usr/bin/pwsh

# Copyright 2021 Dan (Github @LGDan)
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
# OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

#region ED2K Calculator

$ed2kcalc = @"
using System;
using System.Text;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;

namespace Ed2kCalculator
{
    /// <summary>
    ///   Implements the MD4 message digest algorithm in C#
    /// </summary>
    /// <remarks>
    ///   <p>
    ///     <b>References:</b>
    ///     <ol>
    ///       <li> Ronald L. Rivest,
    ///         "<a href = "http://www.roxen.com/rfc/rfc1320.html">
    ///            The MD4 Message-Digest Algorithm</a>",
    ///         IETF RFC-1320 (informational).
    ///       </li>
    ///     </ol>
    ///   </p>
    /// </remarks>
    internal class MD4
    {
        // MD4 specific object variables
        //-----------------------------------------------------------------------

        /// <summary>
        ///   The size in bytes of the input block to the transformation algorithm
        /// </summary>
        private const int BLOCK_LENGTH = 64; // = 512 / 8

        /// <summary>
        ///   512-bit work buffer = 16 x 32-bit words
        /// </summary>
        private readonly uint[] X = new uint[16];

        /// <summary>
        ///   4 32-bit words (interim result)
        /// </summary>
        private readonly uint[] context = new uint[4];

        /// <summary>
        ///   512-bit input buffer = 16 x 32-bit words holds until it reaches 512 bits
        /// </summary>
        private byte[] buffer = new byte[BLOCK_LENGTH];

        /// <summary>
        ///   Number of bytes procesed so far mod. 2 power of 64.
        /// </summary>
        private long count;


        // Constructors
        //------------------------------------------------------------------------
        public MD4()
        {
            EngineReset();
        }

        /// <summary>
        ///   This constructor is here to implement the clonability of this class
        /// </summary>
        /// <param name = "md"> </param>
        private MD4(MD4 md) : this()
        {
            //this();
            context = (uint[]) md.context.Clone();
            buffer = (byte[]) md.buffer.Clone();
            count = md.count;
        }

        // Clonable method implementation
        //-------------------------------------------------------------------------
        public object Clone()
        {
            return new MD4(this);
        }

        // JCE methods
        //-------------------------------------------------------------------------

        /// <summary>
        ///   Resets this object disregarding any temporary data present at the
        ///   time of the invocation of this call.
        /// </summary>
        private void EngineReset()
        {
            // initial values of MD4 i.e. A, B, C, D
            // as per rfc-1320; they are low-order byte first
            context[0] = 0x67452301;
            context[1] = 0xEFCDAB89;
            context[2] = 0x98BADCFE;
            context[3] = 0x10325476;
            count = 0L;
            for (int i = 0; i < BLOCK_LENGTH; i++)
                buffer[i] = 0;
        }


        /// <summary>
        ///   Continues an MD4 message digest using the input byte
        /// </summary>
        /// <param name = "b">byte to input</param>
        private void EngineUpdate(byte b)
        {
            // compute number of bytes still unhashed; ie. present in buffer
            var i = (int) (count%BLOCK_LENGTH);
            count++; // update number of bytes
            buffer[i] = b;
            if (i == BLOCK_LENGTH - 1)
                Transform(ref buffer, 0);
        }

        /// <summary>
        ///   MD4 block update operation
        /// </summary>
        /// <remarks>
        ///   Continues an MD4 message digest operation by filling the buffer,
        ///   transform(ing) data in 512-bit message block(s), updating the variables
        ///   context and count, and leaving (buffering) the remaining bytes in buffer
        ///   for the next update or finish.
        /// </remarks>
        /// <param name = "input">input block</param>
        /// <param name = "offset">start of meaningful bytes in input</param>
        /// <param name = "len">count of bytes in input blcok to consider</param>
        private void EngineUpdate(byte[] input, int offset, int len)
        {
            // make sure we don't exceed input's allocated size/length
            if (offset < 0 || len < 0 || (long) offset + len > input.Length)
                throw new ArgumentOutOfRangeException();

            // compute number of bytes still unhashed; ie. present in buffer
            var bufferNdx = (int) (count%BLOCK_LENGTH);
            count += len; // update number of bytes
            int partLen = BLOCK_LENGTH - bufferNdx;
            int i = 0;
            if (len >= partLen)
            {
                Array.Copy(input, offset + i, buffer, bufferNdx, partLen);

                Transform(ref buffer, 0);

                for (i = partLen; i + BLOCK_LENGTH - 1 < len; i += BLOCK_LENGTH)
                    Transform(ref input, offset + i);
                bufferNdx = 0;
            }
            // buffer remaining input
            if (i < len)
                Array.Copy(input, offset + i, buffer, bufferNdx, len - i);
        }

        /// <summary>
        ///   Completes the hash computation by performing final operations such
        ///   as padding.  At the return of this engineDigest, the MD engine is
        ///   reset.
        /// </summary>
        /// <returns>the array of bytes for the resulting hash value.</returns>
        private byte[] EngineDigest()
        {
            // pad output to 56 mod 64; as RFC1320 puts it: congruent to 448 mod 512
            var bufferNdx = (int) (count%BLOCK_LENGTH);
            int padLen = (bufferNdx < 56) ? (56 - bufferNdx) : (120 - bufferNdx);

            // padding is always binary 1 followed by binary 0's
            var tail = new byte[padLen + 8];
            tail[0] = 0x80;

            // append length before final transform
            // save number of bits, casting the long to an array of 8 bytes
            // save low-order byte first.
            for (int i = 0; i < 8; i++)
                tail[padLen + i] = (byte) ((count*8) >> (8*i));

            EngineUpdate(tail, 0, tail.Length);

            var result = new byte[16];
            // cast this MD4's context (array of 4 uints) into an array of 16 bytes.
            for (int i = 0; i < 4; i++)
            for (int j = 0; j < 4; j++)
                result[i*4 + j] = (byte) (context[i] >> (8*j));

            // reset the engine
            EngineReset();
            return result;
        }

        /// <summary>
        ///   Returns a byte hash from a string
        /// </summary>
        /// <param name = "s">string to hash</param>
        /// <returns>byte-array that contains the hash</returns>
        public byte[] GetByteHashFromString(string s)
        {
            byte[] b = Encoding.UTF8.GetBytes(s);
            var md4 = new MD4();

            md4.EngineUpdate(b, 0, b.Length);

            return md4.EngineDigest();
        }

        /// <summary>
        ///   Returns a binary hash from an input byte array
        /// </summary>
        /// <param name = "b">byte-array to hash</param>
        /// <returns>binary hash of input</returns>
        public byte[] GetByteHashFromBytes(byte[] b)
        {
            var md4 = new MD4();

            md4.EngineUpdate(b, 0, b.Length);

            return md4.EngineDigest();
        }

        /// <summary>
        ///   Returns a string that contains the hexadecimal hash
        /// </summary>
        /// <param name = "b">byte-array to input</param>
        /// <returns>String that contains the hex of the hash</returns>
        public string GetHexHashFromBytes(byte[] b)
        {
            byte[] e = GetByteHashFromBytes(b);
            return BytesToHex(e, e.Length);
        }

        /// <summary>
        ///   Returns a byte hash from the input byte
        /// </summary>
        /// <param name = "b">byte to hash</param>
        /// <returns>binary hash of the input byte</returns>
        public byte[] GetByteHashFromByte(byte b)
        {
            var md4 = new MD4();

            md4.EngineUpdate(b);

            return md4.EngineDigest();
        }

        /// <summary>
        ///   Returns a string that contains the hexadecimal hash
        /// </summary>
        /// <param name = "b">byte to hash</param>
        /// <returns>String that contains the hex of the hash</returns>
        public string GetHexHashFromByte(byte b)
        {
            byte[] e = GetByteHashFromByte(b);
            return BytesToHex(e, e.Length);
        }

        /// <summary>
        ///   Returns a string that contains the hexadecimal hash
        /// </summary>
        /// <param name = "s">string to hash</param>
        /// <returns>String that contains the hex of the hash</returns>
        public string GetHexHashFromString(string s)
        {
            byte[] b = GetByteHashFromString(s);
            return BytesToHex(b, b.Length);
        }

        public static string BytesToHex(byte[] a, int len)
        {
            string temp = BitConverter.ToString(a);

            // We need to remove the dashes that come from the BitConverter
            var sb = new StringBuilder((len - 2)/2); // This should be the final size

            for (int i = 0; i < temp.Length; i++)
                if (temp[i] != '-')
                    sb.Append(temp[i]);

            return sb.ToString();
        }

        // own methods
        //-----------------------------------------------------------------------------------

        /// <summary>
        ///   MD4 basic transformation
        /// </summary>
        /// <remarks>
        ///   Transforms context based on 512 bits from input block starting
        ///   from the offset'th byte.
        /// </remarks>
        /// <param name = "block">input sub-array</param>
        /// <param name = "offset">starting position of sub-array</param>
        private void Transform(ref byte[] block, int offset)
        {
            // decodes 64 bytes from input block into an array of 16 32-bit
            // entities. Use A as a temp var.
            for (int i = 0; i < 16; i++)
                X[i] = ((uint) block[offset++] & 0xFF) |
                       (((uint) block[offset++] & 0xFF) << 8) |
                       (((uint) block[offset++] & 0xFF) << 16) |
                       (((uint) block[offset++] & 0xFF) << 24);


            uint A = context[0];
            uint B = context[1];
            uint C = context[2];
            uint D = context[3];

            A = FF(A, B, C, D, X[0], 3);
            D = FF(D, A, B, C, X[1], 7);
            C = FF(C, D, A, B, X[2], 11);
            B = FF(B, C, D, A, X[3], 19);
            A = FF(A, B, C, D, X[4], 3);
            D = FF(D, A, B, C, X[5], 7);
            C = FF(C, D, A, B, X[6], 11);
            B = FF(B, C, D, A, X[7], 19);
            A = FF(A, B, C, D, X[8], 3);
            D = FF(D, A, B, C, X[9], 7);
            C = FF(C, D, A, B, X[10], 11);
            B = FF(B, C, D, A, X[11], 19);
            A = FF(A, B, C, D, X[12], 3);
            D = FF(D, A, B, C, X[13], 7);
            C = FF(C, D, A, B, X[14], 11);
            B = FF(B, C, D, A, X[15], 19);

            A = GG(A, B, C, D, X[0], 3);
            D = GG(D, A, B, C, X[4], 5);
            C = GG(C, D, A, B, X[8], 9);
            B = GG(B, C, D, A, X[12], 13);
            A = GG(A, B, C, D, X[1], 3);
            D = GG(D, A, B, C, X[5], 5);
            C = GG(C, D, A, B, X[9], 9);
            B = GG(B, C, D, A, X[13], 13);
            A = GG(A, B, C, D, X[2], 3);
            D = GG(D, A, B, C, X[6], 5);
            C = GG(C, D, A, B, X[10], 9);
            B = GG(B, C, D, A, X[14], 13);
            A = GG(A, B, C, D, X[3], 3);
            D = GG(D, A, B, C, X[7], 5);
            C = GG(C, D, A, B, X[11], 9);
            B = GG(B, C, D, A, X[15], 13);

            A = HH(A, B, C, D, X[0], 3);
            D = HH(D, A, B, C, X[8], 9);
            C = HH(C, D, A, B, X[4], 11);
            B = HH(B, C, D, A, X[12], 15);
            A = HH(A, B, C, D, X[2], 3);
            D = HH(D, A, B, C, X[10], 9);
            C = HH(C, D, A, B, X[6], 11);
            B = HH(B, C, D, A, X[14], 15);
            A = HH(A, B, C, D, X[1], 3);
            D = HH(D, A, B, C, X[9], 9);
            C = HH(C, D, A, B, X[5], 11);
            B = HH(B, C, D, A, X[13], 15);
            A = HH(A, B, C, D, X[3], 3);
            D = HH(D, A, B, C, X[11], 9);
            C = HH(C, D, A, B, X[7], 11);
            B = HH(B, C, D, A, X[15], 15);

            context[0] += A;
            context[1] += B;
            context[2] += C;
            context[3] += D;
        }

        // The basic MD4 atomic functions.

        private uint FF(uint a, uint b, uint c, uint d, uint x, int s)
        {
            uint t = a + ((b & c) | (~b & d)) + x;
            return t << s | t >> (32 - s);
        }

        private uint GG(uint a, uint b, uint c, uint d, uint x, int s)
        {
            uint t = a + ((b & (c | d)) | (c & d)) + x + 0x5A827999;
            return t << s | t >> (32 - s);
        }

        private uint HH(uint a, uint b, uint c, uint d, uint x, int s)
        {
            uint t = a + (b ^ c ^ d) + x + 0x6ED9EBA1;
            return t << s | t >> (32 - s);
        }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    public class ed2kCalculator
    {
        private readonly MD4 _md4 = new MD4();

        public const int ED2K_CHUNK_SIZE = 9728000;

        public IEnumerable<CalculationResult> Calc(IEnumerable<FileInfo> files)
        {
            return files.Select(Calc);
        }

        public CalculationResult Calc(FileInfo file)
        {
            CalculationResult result = null;
            using (var stream = file.OpenRead())
            {
                var totalChunkCount = Math.Ceiling(file.Length * 1.0 / ED2K_CHUNK_SIZE);
                var chunkCount = 0;
                var bufferLength = 0;
                var buffer = new byte[ED2K_CHUNK_SIZE];
                var md4HashedBytes = new List<byte>();
                string hash = null;
                while ((bufferLength = stream.Read(buffer, 0, ED2K_CHUNK_SIZE)) > 0)
                {
                    ++chunkCount;
                    var chunkMd4HashedBytes = _md4.GetByteHashFromBytes(buffer.Take(bufferLength).ToArray());
                    md4HashedBytes.AddRange(chunkMd4HashedBytes);
                    //Program.ClearLine();
                    //Console.Write($"{chunkCount}/{totalChunkCount}: {file.Name} ");
                    buffer = new byte[ED2K_CHUNK_SIZE];
                }
                //Program.ClearLine();
                hash = chunkCount > 1
                    ? _md4.GetHexHashFromBytes(md4HashedBytes.ToArray())
                    : MD4.BytesToHex(md4HashedBytes.ToArray(), md4HashedBytes.Count);
                result = new CalculationResult(file, hash);
            }
            return result;
        }
    }

    public class CalculationResult
    {
        public FileInfo File { get; protected set; }
        public string Hash { get; protected set; }

        // ReSharper disable once InconsistentNaming
        public string Ed2kLink => $"ed2k://|file|{Uri.EscapeUriString(File.Name)}|{File.Length}|{Hash}|/";

        public CalculationResult(FileInfo file, string hash)
        {
            if (file == null) throw new ArgumentNullException(nameof(file));
            if (hash == null) throw new ArgumentNullException(nameof(hash));
            File = file;
            Hash = hash;
        }

        public override string ToString()
        {
            return $"{File.FullName}\t{File.Length}\t{File.LastWriteTime:yyyy-MM-dd HH:mm:ss}\t{Hash}";
        }
    }
}

namespace AniDBHelpers
{
    public static class Helpers
    {
        public enum RETURN_CODE
        {
            LOGIN_ACCEPTED                           = 200,
            LOGIN_ACCEPTED_NEW_VERSION               = 201,
            MYLIST_ENTRY_ADDED                       = 210,
            MYLIST_ENTRY_DELETED                     = 211,
            FILE                                     = 220,
            MYLIST_STATS                             = 222,
            ANIME                                    = 230,
            FILE_ALREADY_IN_MYLIST                   = 310,
            MYLIST_ENTRY_EDITED                      = 311,
            NO_SUCH_FILE                             = 320,
            NO_SUCH_ENTRY                            = 321,
            NO_SUCH_ANIME                            = 330,
            NO_SUCH_GROUP                            = 350,
            NO_SUCH_MYLIST_ENTRY                     = 411,
            LOGIN_FAILED                             = 500,
            LOGIN_FIRST                              = 501,
            ACCESS_DENIED                            = 502,
            CLIENT_VERSION_OUTDATED                  = 503,
            CLIENT_BANNED                            = 504,
            ILLEGAL_INPUT_OR_ACCESS_DENIED           = 505,
            INVALID_SESSION                          = 506,
            INTERNAL_SERVER_ERROR                    = 600,
            ANIDB_OUT_OF_SERVICE                     = 601,
            SERVER_BUSY                              = 602
        };

        public enum ACODE
        {
            GROUP_NAME          = 0x00000001,
            GROUP_NAME_SHORT    = 0x00000002,
            EPISODE_NUMBER      = 0x00000100,
            EPISODE_NAME        = 0x00000200,
            EPISODE_NAME_ROMAJI = 0x00000400,
            EPISODE_NAME_KANJI  = 0x00000800,
            EPISODE_TOTAL       = 0x00010000,
            EPISODE_LAST        = 0x00020000,
            ANIME_YEAR          = 0x00040000,
            ANIME_TYPE          = 0x00080000,
            ANIME_NAME_ROMAJI   = 0x00100000,
            ANIME_NAME_KANJI    = 0x00200000,
            ANIME_NAME_ENGLISH  = 0x00400000,
            ANIME_NAME_OTHER    = 0x00800000,
            ANIME_NAME_SHORT    = 0x01000000,
            ANIME_SYNONYMS      = 0x02000000,
            ANIME_CATAGORY      = 0x04000000
        };

        public enum FCODE
        {
            AID           = 0x00000002,
            EID           = 0x00000004,
            GID           = 0x00000008,
            LID           = 0x00000010,
            STATUS        = 0x00000100,
            SIZE          = 0x00000200,
            ED2K          = 0x00000400,
            MD5           = 0x00000800,
            SHA1          = 0x00001000,
            CRC32         = 0x00002000,
            LANG_DUB      = 0x00010000,
            LANG_SUB      = 0x00020000,
            QUALITY       = 0x00040000,
            SOURCE        = 0x00080000,
            CODEC_AUDIO   = 0x00100000,
            BITRATE_AUDIO = 0x00200000,
            CODEC_VIDEO   = 0x00400000,
            BITRATE_VIDEO = 0x00800000,
            RESOLUTION    = 0x01000000,
            FILETYPE      = 0x02000000,
            LENGTH        = 0x04000000,
            DESCRIPTION   = 0x08000000
        };

        public enum anime_amask_ez : Int32
        {
            AID,
            DATEFLAGS,
            YEAR,
            TYPE,
            RELATED_AID_LIST,
            RELATED_AID_TYPE,
            B1_1_RETIRED,
            B1_0_RETIRED,
            ROMANJI_NAME,
            KANJI_NAME,
            ENGLISH_NAME,
            OTHER_NAME,
            SHORT_NAME_LIST,
            SYNONYM_LIST,
            B2_1_RETIRED,
            B2_0_RETIRED,
            EPISODES,
            HIGHEST_EPISODE_NUMBER,
            SPECIAL_EPISODE_COUNT,
            AIR_DATE,
            END_DATE,
            URL,
            PICNAME,
            B3_0_RETIRED,
            RATING,
            VOTE_COUNT,
            TEMP_RATING,
            TEMP_VOTE_COUNT,
            AVERAGE_REVIEW_RATING,
            REVIEW_COUNT,
            AWARD_LIST,
            IS_18PLUS_RESTRICTED,
            B5_7_RETIRED,
            ANN_ID,
            ALLCINEMA_ID,
            ANIMENFO_ID,
            TAG_NAME_LIST,
            TAG_ID_LIST,
            TAG_WEIGHT_LIST,
            DATE_RECORD_UPDATED,
            CHARACTER_ID_LIST,
            B6_6_RETIRED,
            B6_5_RETIRED,
            B6_4_RETIRED,
            B6_3_UNUSED,
            B6_2_UNUSED,
            B6_1_UNUSED,
            B6_0_UNUSED,
            SPECIALS_COUNT,
            CREDITS_COUNT,
            OTHER_COUNT,
            TRAILER_COUNT,
            PARODY_COUNT,
            B7_2_UNUSED,
            B7_1_UNUSED,
            B7_0_UNUSED
        };

        public enum file_amask_ez : Int32
        {
            ANIME_TOTAL_EPISODES,
            HIGHEST_EPISODE_NUMBER,
            YEAR,
            TYPE,
            RELATED_AID_LIST,
            RELATED_AID_TYPE,
            CATEGORY_LIST,
            B1_0_RESERVED,
            ROMANJI_NAME,
            KANJI_NAME,
            ENGLISH_NAME,
            OTHER_NAME,
            SHORT_NAME_LIST,
            SYNONYM_LIST,
            B2_1_RETIRED,
            B2_0_RETIRED,
            EPNO,
            EP_NAME,
            EP_ROMANJI_NAME,
            EP_KANJI_NAME,
            EPISODE_RATING,
            EPISODE_VOTE_COUNT,
            B3_1_UNUSED,
            B3_0_UNUSED,
            GROUP_NAME,
            GROUP_SHORT_NAME,
            B4_5_UNUSED,
            B4_4_UNUSED,
            B4_3_UNUSED,
            B4_2_UNUSED,
            B4_1_UNUSED,
            DATE_AID_RECORD_UPDATED
        };

        public enum file_fmask_ez : Int32
        {
            B1_7_UNUSED,
            AID,
            EID,
            GID,
            MYLIST_ID,
            OTHER_EPISODES,
            IS_DEPRECATED,
            STATE,
            SIZE,
            ED2K,
            MD5,
            SHA1,
            CRC32,
            B2_2_UNUSED,
            VIDEO_COLOUR_DEPTH,
            B2_0_RESERVED,
            QUALITY,
            SOURCE,
            AUDIO_CODEC_LIST,
            AUDIO_BITRATE_LIST,
            VIDEO_CODEC,
            VIDEO_BITRATE,
            VIDEO_RESOLUTION,
            FILE_TYPE_EXTENSION,
            DUB_LANGUAGE,
            SUB_LANGUAGE,
            LENGTH_IN_SECONDS,
            DESCRIPTION,
            AIRED_DATE,
            B4_2_UNUSED,
            B4_1_UNUSED,
            ANIDB_FILE_NAME,
            MYLIST_STATE,
            MYLIST_FILESTATE,
            MYLIST_VIEWED,
            MYLIST_VIEWDATE,
            MYLIST_STORAGE,
            MYLIST_SOURCE,
            MYLIST_OTHER,
            B5_0_UNUSED
        };
    }
}
"@

Add-Type -TypeDefinition $ed2kcalc -Language CSharp

function Get-Ed2kHash($filePath) {
    [Ed2kCalculator.ed2kCalculator]$ed2kCalc = [Ed2kCalculator.ed2kCalculator]::new()
    $fileInfo = [System.IO.FileInfo]::new($filePath)
    $ed2kCalc.Calc($fileInfo)
}

#endregion

#region Core API Interaction

function Get-AniDBAPISocket() {
    $socket = [System.Net.Sockets.UdpClient]::new("api.anidb.info", 9000)
    $socket
}

function Send-AniDBKeepalive($udpSocket) {
    $pingString = New-AniDBMessage -command "PING"
    Get-AniDBApiResponse -requestMessage $pingString -udpSocket $udpSocket
}

function New-AniDBMessage([string]$command, [hashtable]$parameters) {
    $sb = [System.Text.StringBuilder]::new()
    $sb.Append("$command") | Out-Null
    $sb.Append(" ") | Out-Null
    if ($null -ne $parameters) {
        $parameters.GetEnumerator() | ForEach-Object {
            $sb.Append(($_.Key + "=" + $_.Value + "&")) | Out-Null
        }
    }
    $sb.Append("tag=adbrenps-" + (Get-Random -Minimum 1 -Maximum 65535)) | Out-Null
    $sb.ToString()
}

function Get-AniDBApiRawResponse([string]$requestMessage, [System.Net.Sockets.UdpClient]$udpSocket) {
    $rawBytes = [System.Text.Encoding]::UTF8.GetBytes($requestMessage)
    $udpSocket.Send($rawBytes, $rawBytes.Length) | Out-Null
    $timeout = 2000
    $ia = $udpSocket.BeginReceive($null, $null)
    Start-Sleep -Milliseconds $timeout
    $endpoint = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::None,0)
    $result = $udpSocket.EndReceive($ia, [ref]$endpoint)
    if ($null -ne $result) {
        #Write-Host ([System.Text.Encoding]::UTF8).GetString($result)
        $result
    }
}

function Get-AniDBStructuredResponse($bytes) {
    $responseString = ([System.Text.Encoding]::UTF8).GetString($bytes)
    Write-Debug ("< $responseString")
    $tag = ""
    $responseCode = ""
    $responseMessage = ""
    $dataContent = $null

    if ($responseString.Contains("`n")) {
        # Multiline Response
        $lines = $responseString.Split("`n")
        $header = $lines[0]
        $tag = $header.Split(" ")[0]
        $responseCode = $header.Split(" ")[1]
        #$responseMessage = $header.Split(" ")[2]
        $responseMessage = $header.Substring($header.IndexOf(" ",$header.IndexOf($responseCode))+1)
        $dataContent = $responseString.Substring($responseString.IndexOf("`n")+1)
    }else{
        # Single Line Response
        $tag = $responseString.Split(" ")[0]
        $responseCode = $responseString.Split(" ")[1]
        $responseMessage = $responseString.Substring($responseString.IndexOf(" ",$responseString.IndexOf($responseCode))+1)
        #$responseMessage = $responseString.Split(" ")[2]
    }
    [pscustomobject]@{
        Tag=$tag
        ResponseCode=$responseCode
        ResponseMessage=$responseMessage
        DataContent=$dataContent
    }
}

function Get-AniDBApiResponse([string]$requestMessage, [System.Net.Sockets.UdpClient]$udpSocket) {
    Write-Debug -Message ("> $requestMessage")
    $rawByteResponse = Get-AniDBApiRawResponse -requestMessage $requestMessage -udpSocket $udpSocket
    $structuredResponse = Get-AniDBStructuredResponse -bytes $rawByteResponse
    $terminatingCodes = (
        "555",
        "600",
        "601",
        "602"
    )
    if ($structuredResponse.ResponseCode -in $terminatingCodes) {
        Write-Error -Message ("WOAH. Unexpected response code " + $structuredResponse.ResponseCode + ".")
        break
    }else{
        $structuredResponse
    }
}

function ConvertFrom-AniDBPSV([String]$inputData, [System.Collections.ArrayList]$headings) {
    $rows = $inputData.Split("`n")
    $rows | ForEach-Object {
        if ($_.Length -gt 0) {
            $fields = $_.Split("|")
            $rowHT = [ordered]@{}
            for ($i=0;$i-lt$fields.Length;$i++){
                $rowHT.Add($headings[$i],$fields[$i]) | Out-Null
            }
            $rowHT
        }
    }
}

#endregion

#region Logins and Auth

function Get-AniDBSessionKey($AniDBUsername, $AniDBPassword, $udpSocket) {
    $authString = New-AniDBMessage -command "AUTH" -parameters @{
        user=$AniDBUsername
        pass=$AniDBPassword
        protover=3 #int4 apiversion
        client="adbrenps"
        clientver=1
        nat=1 #Nat used
        #comp=1 #no compression ty
        enc="UTF8" 
    }
    Get-AniDBApiResponse -requestMessage $authString -udpSocket $udpSocket
}

function Remove-AniDBSessionKey($sessionKey, $udpSocket) {
    $logoutString = New-AniDBMessage -command "LOGOUT" -parameters @{
        s=$sessionKey
    }
    Get-AniDBApiResponse -requestMessage $logoutString -udpSocket $udpSocket
}

function Invoke-AniDBLogin($username, $password) {
    if ($null -eq $global:sock) {
        $global:sock = Get-AniDBAPISocket
        Write-Debug -Message "New UDP socket created."
    }else{
        Write-Debug -Message "Already logged in."
        $false
    }
    $sessionKeyResponse = Get-AniDBSessionKey -AniDBUsername $username -AniDBPassword $password -udpSocket $global:sock
    if ($sessionKeyResponse.ResponseCode.StartsWith("20")) {
        $sessionKey = $sessionKeyResponse.ResponseMessage.Split(" ")[0]
        $global:sessionKey = $sessionKey
        Write-Debug -Message "Logged in."
        $true
    }else{
        Write-Debug -Message "Error logging in."
        $false
    }
}

function Invoke-AniDBLogout() {
    if (($null -ne $global:sock) -and ($null -ne $global:sessionKey)) {
        $endResponse = Remove-AniDBSessionKey -sessionKey $sessionKey -udpSocket $global:sock
        if ($endResponse.ResponseCode -eq "203") {
            # Logged Out Successfully.
            ([System.Net.Sockets.UdpClient]$global:sock).Dispose() | Out-Null
            $global:sock = $null
            Write-Debug -Message "Logged out."
            $true
        }else{
            # Logout Failed.
            Write-Debug -Message "Error logging out. Bad response code returned."
        }
    }else{
        Write-Debug -Message "Error logging out. Either not connected or no session present."
    }
}

function Invoke-QuickApiLogin() {
    $username = $Global:config["anidb_username"]
    $password = $Global:config["anidb_password"]
    Invoke-AniDBLogin -username $username -password $password
}

function Invoke-AniDBApiLoginIfRequired() {
    Write-Debug ("Logging required for action.")
    if ($null -eq $Global:sessionKey) {
        Write-Debug ("Logging In...")
        Invoke-QuickApiLogin
    }else{
        Write-Debug ("Already logged in.")
    }
}

#endregion

#region Direct API Abstractions (UDP API)

function Get-AniDBApiFileInfo($ed2kHash, $fileSize, $fileMask, $animeMask, $sessionKey, $udpSocket) {
    $fileCommand = New-AniDBMessage -command "FILE" -parameters ([ordered]@{
        size=$fileSize
        ed2k=$ed2kHash
        fmask=$fileMask
        amask=$animeMask
        s=$sessionKey
    })
    Get-AniDBApiResponse -requestMessage $fileCommand -udpSocket $udpSocket
}

function Get-AniDBApiAnime($aid) {
    Write-Debug ("Anime $aid requested from API.")

    [Int32[]]$requested_fields = (
        [Int32][AniDBHelpers.Helpers+anime_amask_ez]::AID,
        [Int32][AniDBHelpers.Helpers+anime_amask_ez]::YEAR,
        [Int32][AniDBHelpers.Helpers+anime_amask_ez]::TYPE,
        [Int32][AniDBHelpers.Helpers+anime_amask_ez]::ROMANJI_NAME,
        [Int32][AniDBHelpers.Helpers+anime_amask_ez]::KANJI_NAME,
        [Int32][AniDBHelpers.Helpers+anime_amask_ez]::ENGLISH_NAME
    )

    Write-Debug ("Preparing amask...")
    $amask = Get-AniDBAnimeAnimeMask -requestedFields $requested_fields

    $message = New-AniDBMessage -command "ANIME" -parameters @{
        aid=$aid
        amask=$amask
        s=$Global:sessionKey
    }

    Write-Debug ("Requesting $aid...")
    Invoke-AniDBApiLoginIfRequired | Out-Null
    $response = Get-AniDBApiResponse -requestMessage $message -udpSocket $Global:sock

    if ($response.ResponseCode -eq "230") {
        # Success
        Write-Debug ("Successfully queried $aid.")
        [System.Collections.ArrayList]$columnHeaders = @()
        $anime_amask_field_names = [Enum]::GetNames([AniDBHelpers.Helpers+anime_amask_ez])
        $requested_fields | ForEach-Object {
            $columnHeaders.Add($anime_amask_field_names[$_]) | Out-Null
        }
        ConvertFrom-AniDBPSV -inputData $response.DataContent -headings $columnHeaders
    }else{
        Write-Host ("Error.")
    }
}

function Get-AniDBFile($ed2kHash, $fileSize, $fields) {
    # This function actually talks to the API and does not talk to the cache.

    # Prep the fields...
    Write-Debug ("Preparing Fields...")
    $fmask = Get-AniDBFileFileMask -requestedFields $fields.FMaskFields
    $amask = Get-AniDBFileAnimeMask -requestedFields $fields.AMaskFields
    
    # Request the info
    Write-Debug ("Requesting API Info...")
    Invoke-AniDBApiLoginIfRequired | Out-Null
    $fileInfoResponse = Get-AniDBApiFileInfo `
        -ed2kHash $fileMeta.Hash `
        -fileSize $fileMeta.Size `
        -fileMask $fmask `
        -animeMask $amask `
        -sessionKey $global:sessionKey `
        -udpSocket $global:sock

    # Did it work?
    if ($fileInfoResponse.ResponseCode -eq "220") {
        # Parse the results
        ConvertFrom-AniDBPSV -inputData $fileInfoResponse.DataContent -headings $fields.ColumnHeaders
    }else{
        Write-Host ("Error.")
    }

    # Save the last results data anyway.
    $fileInfoResponse | ConvertTo-Json -Depth 2 | Out-File "anidbFileResponse.json"        
    Write-Debug ("Saved last results.")
}

#endregion

#region Mask Manipulation

function Get-AniDBFileAnimeMask([Int32[]]$requestedFields) {
    [Char[]]$amask_bits = "00000000000000000000000000000000"
    $requestedFields | ForEach-Object {
        $amask_bits[$_] = "1"
    }
    $amask = [Convert]::ToInt32(([String]$amask_bits).Replace(" ",""),2).ToString("X")
    if (($amask.Length % 2) -ne 0) {
        $amask = ("0" + $amask)
    }
    $amask = $amask.PadLeft(8,"0")
    $amask
}

function Get-AniDBFileFileMask([Int32[]]$requestedFields) {
    [Char[]]$fmask_bits = "0000000000000000000000000000000000000000"
    $requestedFields | ForEach-Object {
        $fmask_bits[$_] = "1"
    }
    $fmask = [Convert]::ToInt64(([String]$fmask_bits).Replace(" ",""),2).ToString("X")
    $fmask = $fmask.PadLeft(10,"0")
    $fmask
}

function Get-AniDBAnimeAnimeMask([Int32[]]$requestedFields) {
    [Char[]]$fmask_bits = "00000000000000000000000000000000000000000000000000000000"
    $requestedFields | ForEach-Object {
        $fmask_bits[$_] = "1"
    }
    $fmask = [Convert]::ToInt64(([String]$fmask_bits).Replace(" ",""),2).ToString("X")
    $fmask = $fmask.PadLeft(14,"0")
    $fmask
}


#endregion

#region Internal Caching

function Get-AniDBCache($entityName) {
    $basePath = ""
    if ("" -eq $PSScriptRoot) {
        # Running in Dev Env
        Write-Debug -Message ("Cache detected running in dev.")
        $basePath = $PWD.Path
    }else{
        # Running in Script Mode
        Write-Debug -Message ("Cache detected running in script.")
        $basePath = $PSScriptRoot
    }
    $cacheDirectory = ($basePath + "/cache/$entityName")
    if (!(Test-Path $cacheDirectory)) {
        Write-Debug -Message ("Cache directory $cacheDirectory does not exist.")
        New-Item -Path $cacheDirectory -ItemType Directory | Out-Null
        Write-Debug -Message ("Cache directory created.")
    }
    $cacheDirectory
}

#endregion

#region Files

function Get-FileMetaForAniDBSearch($filePath) {
    [pscustomobject]@{
        Hash=(Get-Ed2kHash -filePath $filePath).Hash.ToLower()
        Size=[System.IO.FileInfo]::new($filePath).Length
    }
}

function Get-AniDBFieldsFromFormatString($format) {
    # File Mask First
    [System.Collections.ArrayList]$fmask_fields = @()
    $fmask_field_names = [Enum]::GetNames([AniDBHelpers.Helpers+file_fmask_ez])
    $fmask_field_names | ForEach-Object {
        # Manually add AID for Title Lookup
        # It's important that the fields are added in order here...
        # No adding fields in the wrong order or the output gets screwed.
        if ($_ -eq "AID") {
            $fmask_fields.Add([Enum]::Parse([AniDBHelpers.Helpers+file_fmask_ez],"AID")) | Out-Null
        }else{
            # For any others, Add normally.
            $variableized = ("%" + $_.ToLower() + "%")
            if ($format.Contains($variableized)) {
                $fmask_fields.Add([Enum]::Parse([AniDBHelpers.Helpers+file_fmask_ez],$_)) | Out-Null
            }
        }
    }

    # Then Anime Mask
    [System.Collections.ArrayList]$amask_fields = @()
    $amask_field_names = [Enum]::GetNames([AniDBHelpers.Helpers+file_amask_ez])
    $amask_field_names | ForEach-Object {
        $variableized = ("%" + $_.ToLower() + "%")
        if ($format.Contains($variableized)) {
            $amask_fields.Add([Enum]::Parse([AniDBHelpers.Helpers+file_amask_ez],$_)) | Out-Null
        }
    }

    # Store Column Order
    [System.Collections.ArrayList]$columnHeaders = @()
    $columnHeaders.Add("FID") | Out-Null
    $fmask_fields | ForEach-Object {
        $columnHeaders.Add($fmask_field_names[$_]) | Out-Null
    }
    $amask_fields | ForEach-Object {
        $columnHeaders.Add($amask_field_names[$_]) | Out-Null
    }

    [pscustomobject]@{
        FMaskFields=$fmask_fields
        AMaskFields=$amask_fields
        ColumnHeaders=$columnHeaders
    }
}

function Get-AniDBRenameInfo($filePath, $format) {
    # Has a file been specified?
    if (Test-Path -LiteralPath $filePath) {
        # Yes.

        # First, get the fields set up for the request.
        $fields = Get-AniDBFieldsFromFormatString -format $format

        Write-Debug ("Selected File Fields: " + ($fields.FMaskFields))
        Write-Debug ("Selected Anime Fields: " + ($fields.AMaskFields))
        Write-Debug ("Expected Column Order:" + ($fields.ColumnHeaders))

        # Next, Hashing and Metadata
        Write-Debug ("Hashing $filePath..." + (Get-Date).ToLongTimeString())
        $startTime = (Get-Date)
        $fileMeta = Get-FileMetaForAniDBSearch -filePath $filePath
        $duration = [System.Math]::Floor(((Get-Date) - $startTime).TotalSeconds)
        Write-Debug ("Hashing at " + ((($fileMeta.Size / 1MB) / $duration)) + " MB/s")
        Write-Debug ("Hashed $filePath." + (Get-Date).ToLongTimeString())

        # Query cache to see if results are saved...
        Write-Debug ("Getting File Info from cache...")
        [Hashtable]$fileApiResults = Get-AniDBFileCache -ed2kHash $fileMeta.Hash -fileSize $fileMeta.Size -fields $fields
        Write-Debug ("Getting Anime Info from cache...")
        [Hashtable]$animeApiResults = Get-AniDBAnimeCache -aid $fileApiResults.AID

        # Title Logic, because some anime has an english name by default...
        if ($fileApiResults.ContainsKey("ENGLISH_NAME")) {
            $englishName = $animeApiResults.ENGLISH_NAME
            if ($englishName -eq "") {
                $englishName = $animeApiResults.ROMANJI_NAME
            }
            $fileApiResults["ENGLISH_NAME"] = $englishName
        }
        
        # Replace and record what was replaced
        $replacerTable = @{}
        $renamedString = $format
        $fileApiResults.GetEnumerator() | ForEach-Object {
            $toReplace = ("%" + $_.Key.ToLower() + "%")
            $renamedString = $renamedString.Replace($toReplace, $_.Value)
            $replacerTable.Add($toReplace, $_.Value) | Out-Null
        }

        # Return a useful object
        [pscustomobject]@{
            RawFileResult = $fileApiResults
            RawAnimeResult = $animeApiResults
            ReplacerTable = $replacerTable
            FilePath = $filePath
            ResultPath = $renamedString
        }
    }else{
        # No, a file has not been specified.
        Write-Host ("No file specified.")
    }
}

#endregion

#region Cached Access to Data (USE THESE)

function Get-AniDBAnimeCache($aid) {
    $cacheDirectory = Get-AniDBCache -entityName "anime"
    $cacheFile = ($cacheDirectory + "/$aid.json")
    if (!(Test-Path $cacheFile)) {
        Write-Debug -Message ("Anime Cache - requested $aid not in cache. Caching...")
        Get-AniDBApiAnime -aid $aid | ConvertTo-Json -Compress | Out-File $cacheFile -Encoding utf8
    }
    Write-Debug -Message ("Anime Cache - Fetching $aid from cache.")
    Get-Content $cacheFile | ConvertFrom-Json -AsHashtable
}

function Get-AniDBFileCache([String]$ed2kHash, $fileSize, $fields) {
    $cacheDirectory = Get-AniDBCache -entityName "file"
    $cacheFile = ($cacheDirectory + "/$ed2kHash-$fileSize.json")
    if (!(Test-Path $cacheFile)) {
        Write-Debug -Message ("File Cache - requested $ed2kHash not in cache. Caching...")
        $fileInfo = Get-AniDBFile -ed2kHash $ed2kHash -fileSize $fileSize -fields $fields
        $fileInfo | ConvertTo-Json -Compress | Out-File $cacheFile -Encoding utf8
    }
    Write-Debug -Message ("File Cache - Fetching $ed2kHash from cache.")
    Get-Content $cacheFile | ConvertFrom-Json -AsHashtable
}

#endregion

#region Tests

function Test-AniDBApi() {
    $sock = Get-AniDBAPISocket
    $anidbMessage = New-AniDBMessage -command "PING"
    Get-AniDBApiResponse -requestMessage $anidbMessage -udpSocket $sock
    $sock.Dispose()
}

function Test-AniDBApiFileCommand() {
    Write-Debug -Message "Testing File Command"
    $username = $Global:config["anidb_username"]
    $password = $Global:config["anidb_password"]

    if (Invoke-AniDBLogin -username $username -password $password) {
        # What do we want to know?
        #   FID is always returned as data field 0
        [Int32[]]$fmask_fields = (,
            [Int32][AniDBHelpers.Helpers+file_fmask_ez]::FILE_TYPE_EXTENSION
        )
        [Int32[]]$amask_fields = (
            [Int32][AniDBHelpers.Helpers+file_amask_ez]::ENGLISH_NAME,
            [Int32][AniDBHelpers.Helpers+file_amask_ez]::EPNO
        )

        # Convert the choices to hex strings
        $fmask = Get-AniDBFileFileMask -requestedFields $fmask_fields
        $amask = Get-AniDBFileAnimeMask -requestedFields $amask_fields
        
        # Request the info
        $fileInfoResponse = Get-AniDBApiFileInfo `
            -ed2kHash "43df60e1834c0fdd0afc2451dec73413" `
            -fileSize "2016079790" `
            -fileMask $fmask `
            -animeMask $amask `
            -sessionKey $global:sessionKey `
            -udpSocket $global:sock

        # Did it work?
        if ($fileInfoResponse.ResponseCode -eq "220") {
            # Success!

            # Store Column Order
            $fmask_field_names = [Enum]::GetNames([AniDBHelpers.Helpers+file_fmask_ez])
            $amask_field_names = [Enum]::GetNames([AniDBHelpers.Helpers+file_amask_ez])
            [System.Collections.ArrayList]$columnHeaders = @()
            $columnHeaders.Add("FID") | Out-Null
            $fmask_fields | ForEach-Object {
                $columnHeaders.Add($fmask_field_names[$_]) | Out-Null
            }
            $amask_fields | ForEach-Object {
                $columnHeaders.Add($amask_field_names[$_]) | Out-Null
            }

            # Parse the results
            ConvertFrom-AniDBPSV -inputData $fileInfoResponse.DataContent -headings $columnHeaders

        }else{
            # Fail!
            Write-Debug "Error."
        }

        # Save the last results data anyway.
        $fileInfoResponse | ConvertTo-Json -Depth 2 | Out-File "anidbFileResponse.json"        
        Write-Debug Saved last results.

        if (Invoke-AniDBLogout) {
            Write-Debug Logged out
        }
    }
}

function Test-AniDBRenamer() {

    # Example function showing the output of the Get-AniDBRenameInfo command.

    $lookupResult = Get-AniDBRenameInfo `
        -filePath "/Downloads/Steins;Gate - 01 - Turning Point.mkv" `
        -format "/mnt/cloud/anime/%english_name%/%english_name% - %epno% - %ep_name%.%file_type_extension%"
    $lookupResult

    #RawFileResult  : {ENGLISH_NAME, AID, FID, EPNO…}
    #RawAnimeResult : {ENGLISH_NAME, AID, YEAR, ROMANJI_NAME…}
    #ReplacerTable  : {%aid%, %file_type_extension%, %epno%, %fid%…}
    #FilePath       : /Downloads/Steins;Gate - 01 - Turning Point.mkv
    #ResultPath     : /mnt/cloud/anime/Steins;Gate/Steins;Gate - 01 - Turning Point.mkv

    Invoke-AniDBLogout | Out-Null
}

#endregion

#region Main Script Functions

function Show-Logo() {
    Clear-Host
    Write-Host ("-------------------------------") -ForegroundColor Gray
    Write-Host ("> AniDB Renamer PS Edition v1 <") -ForegroundColor Blue
    Write-Host ("-------------------------------") -ForegroundColor Gray
    Write-Host
}

function Import-Config() {
    try {
        Write-Host ("Loading Config...") -NoNewline
        if (!(Test-Path "adbrenps_config.json")) {
            New-Config
        }
        $Global:config = (Get-Content "adbrenps_config.json" | ConvertFrom-Json -AsHashtable)
        Write-Host ("[Done]") -ForegroundColor Green
        $Global:config.GetEnumerator() | ForEach-Object {
            if ($_.Key -notlike "*password*") {
                Write-Host ("  " + $_.Key + ": " + $_.Value)
            }else{
                Write-Host ("  " + $_.Key + ": [redacted]")
            }
        }
        if ($Global:config["debug"] -eq "1") {
            $DebugPreference = 'Continue'
        }else{
            $DebugPreference = 'SilentlyContinue'
        }
    }catch{
        Write-Error ("There was an error loading config.")
        Write-Error $_.Message
        break
    }
}

function New-Config() {
    $raw = @"
{
    "anidb_username": "blah",
    "anidb_password": "blah",
    "source_path": "/anime/source",
    "destination_path": "/anime/destination",
    "debug": "0",
    "destinaton_format": "/%anime_name_english%/%anime_name_english% - %episode% - %episode_name%.%filetype%"
}
"@
    $raw | Out-File "adbrenps_config.json"
}

function Invoke-DoRenames($DirectoryPath) {
    Get-ChildItem -Path $DirectoryPath | Select-Object -ExpandProperty FullName | ForEach-Object {
        Get-AniDBRenameInfo -filePath $_ -format $Global:config["destination_format"]
    } | ForEach-Object {
        # rclone move
    }
}

#endregion

#region Main Script

Show-Logo

Import-Config

try {

}catch{
    $_
}finally{
    # Last command should always be log out!
    Invoke-AniDBLogout
}
#endregion
