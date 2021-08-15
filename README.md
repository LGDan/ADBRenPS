# ADBRenPS
AniDB UDP API Client and File Renamer, written in PowerShell and C#, all in one script. 

- This is not functional right away.
- You will need to use the functions in this script to rename your own files. 
- You will need to know powershell well to use this in its current state.

## Info

This powershell script abstracts the usage of the AniDB API to a set of core functions, with the intention of being used to rename files.

## Usage

Initialise the script with:

```powershell
PS > . ./adbrenps.ps1
```

A new config file will be created in the current directory called `adbrenps_config.json` with some default options.

```json
{
    "anidb_username": "blah",
    "anidb_password": "blah",
    "source_path": "/anime/source",
    "destination_path": "/anime/destination",
    "debug": "0",
    "destinaton_format": "/%anime_name_english%/%anime_name_english% - %episode% - %episode_name%.%filetype%"
}
```

Once loaded, all config properties are accessible via the global config hashtable, `$Global:config`

There are a few useful functions to start with, but the intention for this script is for it to be built upon, or **dot-sourced** from another script.

## Abstractions & Useful Bits

### Bitmasking

The script provides a few pre-made bitmask enums for more nicely handling the masking used by the AniDB API. The C# section at the top of the main file has then defined under  
`[AniDBHelpers.Helpers+enum_name_here]`

The naming convention is `{api-request-type}_{masktype}_ez`  
i.e. `anime_amask_ez`

The enums are written to be index based rather than use native C# bitmasks directly. This is because of the way the AniDB API expects the bitmasks to be presented (it does not like leading characters to be omitted etc.), and the fact that when data is returned, the order is that of which the bitmask bits are ordered. Lookups for columns become easier.

Fields are requested as so:

```powershell
[Int32[]]$requested_fields = (
    [Int32][AniDBHelpers.Helpers+anime_amask_ez]::AID,
    [Int32][AniDBHelpers.Helpers+anime_amask_ez]::YEAR,
    [Int32][AniDBHelpers.Helpers+anime_amask_ez]::TYPE,
    [Int32][AniDBHelpers.Helpers+anime_amask_ez]::ROMANJI_NAME,
    [Int32][AniDBHelpers.Helpers+anime_amask_ez]::KANJI_NAME,
    [Int32][AniDBHelpers.Helpers+anime_amask_ez]::ENGLISH_NAME
)
```

And further functions are provided to correctly return bitmasks in the format that AniDB's API wants it. The example below is for https://wiki.anidb.net/UDP_API_Definition#ANIME:_Retrieve_Anime_Data  (7 bytes with each byte represented as 2 characters, as is stated by the `hexstr` datatype on the same wiki page.)

```powershell
function Get-AniDBAnimeAnimeMask([Int32[]]$requestedFields) {
    [Char[]]$fmask_bits = "00000000000000000000000000000000000000000000000000000000"
    $requestedFields | ForEach-Object {
        $fmask_bits[$_] = "1"
    }
    $fmask = [Convert]::ToInt64(([String]$fmask_bits).Replace(" ",""),2).ToString("X")
    $fmask = $fmask.PadLeft(14,"0")
    $fmask
}
```

## Available Functions

---

### `Invoke-QuickApiLogin`

Logs in to the AniDB UDP API. Required before any other commands can be run.

Arguments:

- None

Example:
```powershell
PS > Invoke-QuickApiLogin

True
```

---

### `Invoke-AniDBLogout`

**If you don't do this on script exit, you will run out of sessions and get banned.**
Logs out of the AniDB UDP API. 

Arguments:

- None

Example:
```powershell
PS > Invoke-AniDBLogout

True
```

---

### `Get-AniDBRenameInfo`

Returns an object useful for renaming files.

Arguments:
- -filePath \<path_to_file.ext>
- -format \<field_format>

Example:

```powershell
PS > Get-AniDBRenameInfo `
        -filePath "/Downloads/Steins;Gate - 01 - Turning Point.mkv" `
        -format "/mnt/cloud/anime/%english_name%/%english_name% - %epno% - %ep_name%.%file_type_extension%"

RawFileResult  : {ENGLISH_NAME, AID, FID, EPNO…}
RawAnimeResult : {ENGLISH_NAME, AID, YEAR, ROMANJI_NAME…}
ReplacerTable  : {%aid%, %file_type_extension%, %epno%, %fid%…}
FilePath       : /Downloads/Steins;Gate - 01 - Turning Point.mkv
ResultPath     : /mnt/cloud/anime/Steins;Gate/Steins;Gate - 01 - Turning Point.mkv
```

Full list of format variables:

(Each must be lowercase, surrounded by % signs, i.e. `%quality%`)

```
# Anime Specific
# ----------------------------
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

# File Specific
# --------------------------
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
```

---

### `Get-AniDBAnimeCache`

Gets simple anime information. Tries local cache first, then queries the UDP API.

Arguments:

- -aid \<anidb_anime_id>

Example:
```powershell
PS > Get-AniDBAnimeCache -aid 7729

Name                           Value
----                           -----
YEAR                           2011-2011
KANJI_NAME                     Steins;Gate
TYPE                           TV Series
ROMANJI_NAME                   Steins;Gate
ENGLISH_NAME                   
AID                            7729

```

---

### `Get-AniDBFileCache`

Gets detailed information on files. Tries local cache first, then queries the UDP API.

Arguments:

- -ed2kHash \<ed2k_hash>
- -fileSize \<file_size_in_bytes>
- -fields \<output-of Get-AniDBFieldsFromFormatString>


Example:
```powershell
$filePath = "/Downloads/episodename.04.idk.blah.mkv"

$format = "%epno% %ep_name% %file_type_extension%"
$fieldData = Get-AniDBFieldsFromFormatString -format $format
$fileMeta = Get-FileMetaForAniDBSearch -filePath $filePath

PS > Get-AniDBFileCache -ed2kHash $fileMeta.Hash -fileSize $fileMeta.Size -fields $fields

FID                 : 1547750
AID                 : 7729
FILE_TYPE_EXTENSION : mkv
ENGLISH_NAME        : 
EPNO                : 01
EP_NAME             : Turning Point
```

---

### `Get-FileMetaForAniDBSearch`

Reads a file from disk, and returns an object with the ED2K hash and file length. This can appear to hang, but hash computation can take a while with larger files on HDDs.

Parameters:

- -filePath \<file path>

Example:

```powershell
PS > Get-FileMetaForAniDBSearch -filePath "/Downloads/Steins;Gate - 01 - Turning Point.mkv"


Hash                                   Size
----                                   ----
76eb90c29c660a2bd9d40c640000869e 1670666764
```

---

### `New-AniDBMessage`

Useful for adding further functionality to the script.

https://wiki.anidb.net/UDP_API_Definition#ANIME:_Retrieve_Anime_Data

Parameters:

- -command \<string>
- -parameters \<hashtable>

Example:

```powershell
$message = New-AniDBMessage -command "ANIME" -parameters @{
    aid=$aid
    amask=$amask
    s=$Global:sessionKey
}
$response = Get-AniDBApiResponse -requestMessage $message -udpSocket $Global:sock

# DEBUG: > ANIME aid=7729&amask=B0E00000000000&s=p26FO&tag=adbrenps-33310
# DEBUG: < adbrenps-33310 230 ANIME
# 7729|2011-2011|TV Series|Steins;Gate|Steins;Gate|

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
```