# Table-Lookup Attack Tool

A Go program designed to perform a table-lookup attack on passwords. This was quickly vibecoded together so excuse any suboptimal code :P

## Overview

This tool reads a substitution table from a file and uses it to generate variations of words from a dictionary file. The goal is to efficiently crack passwords that use leetspeak or other character substitutions such as the research on transliteration by Stealthsploit and T0xlc among others (I know a few more deserve credit for research on this topic but i don't have the names. Feel free to reach out)
Based on: https://hashcat.net/wiki/doku.php?id=table_lookup_attack

## Configuration

The tool requires the following configuration:

* `--table-file`: Path to the substitution table file
* `--dict`: Path to the dictionary file

Optional configuration parameters:

* `--table-min`: Minimum password length (default: 2)
* `--table-max`: Maximum password length (default: 15)
* `--threads`: Number of threads to use (default: number of CPU cores)
* `--substitute-all`: Replicate substitution cipher (replace all occurrences of a character) see: Transliteration

## Substitution Table Format

The substitution table file should contain lines in the format "key=value", where key and value are single Unicode characters. Lines starting with "#" and empty lines are ignored.

Example:
```
a=A
a=@
e=3
i=I
```

## Dictionary File Format

The dictionary file should contain one word per line.

## Output

The tool generates variations of each word in the dictionary file by replacing characters with their corresponding substitutions from the table. The output is a list of generated passwords, one combination per line.

For example, if the dictionary file contains the word "hello" and the substitution table contains the following lines:

```
h=H
e=E
l=L
o=O
```

The output would be: hEllo hELlo hEloo hEloo ...

Each line represents a different combination of substitutions.

## Use Cases

* Cracking leetspeak passwords using a table with common substitutions (e.g., `a=@`, `e=3`, etc.)
* Replacing the toggle-case attack with a table that maps lowercase to uppercase letters (e.g., `a=A`, `b=B`, etc.)
* Combining multiple substitution tables to generate a wider range of passwords
* Performing transliteration attacks by substituting q=a w=z (for qwerty=azerty for example)

# Transliteration Attacks

To perform transliteration attacks with the a5 table generator we decided to use the --substitute-max (-s for short) flag, this flag will try to substitute every character possible and create appropriate permutations for multiple substitutions.
This means that you can run a table to substitute entire keyboards, and still maintain the flexibility of making multiple substitutions of 0=1 0=2 0=3 0=4. The following command is an example running an attack.
```
a5_generator.exe F:\Wordlists\hashmob.net_2025-07-20.found -t .\qwerty-azerty.table -s | hashcat -m 100 .\hashmob.net.100.left -O --bitmap-max 28 -r F:\Rules\hashmob_v0.1.rules
```

Some results:
```
494a3cf354aa67a87728aee45270c10e41880b0c:DESFRENNESéè'
feef0759067e58090fcfafe893db96396a489a02:bOSTONàç&"
f7d42bb8f53b23ae0b9b970ae554762532663d1a:tRUSTçè&
f7dc5ebb00d3a9eabe16c7048e52586a435143ea:IRQDQéà&(
00e3c3fc97d03c680aad9d7fb1a9bda99d4410fe:cHRIST@è"
e7b3bfc4b5396f8fa02dd0c83eec5e291809d1d4:B&çç'gar
ded0b3cec64394219821b744bbc46c779a72852b:çé&"&à"&m
8f7e7926fde170f502a4176521ff4e01352aa369:çàé&àbhng
dbd48d203e0fc7d571d1c70521c57a0e3290f16e:è"§§"çàa
810559e24a90f9022a54636caf507d6a0f98b92d:ç(&("ç&à
90acc138dc2b32bf0f90d3863e6b4a110cb7b382:è"'(&'&è
eacb6afec1d0b55ad8baf984b1adff69d9ddeabe:!"§çgolf
e98f08d84c1336dc19ff1ed2f403fb26cf1d5ae5:""&è(ééç
daeb8cc6e0ea17fc2fce5e09428055e97bb6cdbb:éF*BPYVj8
67cdc3a096a01e4f0ac1ab231a58084c7bc885be:éevz"""(
108fe3b5e6eb99715846db890244bc17d875a8f9:éèééç"&(
97f06b63caf073fda09dfa20e85f72a10edb5d03:&ç&&§(l0l0
a70a4b135be2fc7bd45ab41793036985113db308:&(juilletç(
8cd8089450dbeb0fc75871bdd03fb45b6cf23f9b:&é"ccc'(aa
e5afa0fedb013bb282cd08791b7282c73268fd7d:&&àè&ç!çalin
308a3132ecc8e7afc05149e8a5ef84e9828e5c12:ypcbeàà6
141e41bc670420c12ba467b30364db25fbb641dc:van§§è(
66b4ffed48827209d6538d8f142ebe3d1b5cd476:vaioççé!"robert
197c76e00d04bfd58404dcee08ccb32d376fb553:UéV(KRYHK
029d06afd034c4bf9b2ff3d04d0bb1013328b877:katoè!&"
925b383aee1e17bade32b2fc692fa093b6102e9f:STEVESORBYàç&è
b94abd72d4cf4bbcb46bec0d4120777de0b93b64:sjls''çà
e305d0fd8d30eaaaceefee5ef5cb366562ff7994:Rv&çàçç!
000005d5b17ff1340128af25c38e492e21e8f12a:biekeéèà!
025ae8eb24b2a15cccd14231b5d0d937dd60ac92:Awzxecqsdrfv1235
5022639ef661fd61c03fc9296eb12e3aabc57a2b:§§!!poiu
914ec4acdd67fc957669007f5136a72252bcef57:mp&çç&&ççé
47889524a9eda2566c86d7f159c0c5229bf9dccf:octobreè!(!
```

I encourage playing around with different languages as this is a worldwide occurrence and hindi is just as much affected as chinese or korean. Especially if you consider variations of é or ß.
And consider what direction this operates in. Are you considering your own keyboard to another keyboard, or are you also considering a Chineese person that speaks english and makes the same mistake with their qwerty layout?
```
a5_generator.exe hashmob.net_2025-08-10.micro.found -t azerty-qwerty.rule -t qwerty-azerty.rule 
```
We will generate permutations that goes both ways, first qwerty->azerty and then azerty->qwerty.
But there is an edge case to be considered. What if you do it halfway through your word while trying to reach for symbols? Or what if you have 3 keyboards and you accidentally switch twice? 
This is where you can combine different transformations into a merged file that attempts to do all at the same time in different permutations at different points. It's up to you what characters you decide to do this with as the keyspace increases really quickly.

For example:
```
a=q
q=a
z=w
w=z
m=;
;=m
,=m
A=Q
Q=A
Z=W
W=Z
M=;
;=M
```
Will attempt to do both things both ways, but not cross case such as:
```
a=Q
Q=a
```

The more you add, the more permutations you receive for "typo's".


If you have 1 keyboard you always type the chosen one (example: qwerty). If you have 2 keyboards installed you will be able to switch back and forth.
If you have 3 you can switch back and forth in 3 different ways. If you specify one table file containing q=a w=z then qaw will translate to aaz, but not vice versa.

With all of this in mind I want to recommend a file name standard for keyboard layouts and add them to this repo for those that wish to contribute:
- A single keyboard substituted one way to another keyboard will receive the format of: `qwerty-azerty.table` with `azerty-qwerty.table` being the opposite.
Included in this archive a few examples - these are *incomplete* tables.

#### Here are some examples:

From a qwerty to azerty keyboard and qwerty to a partial greek you can run the following command. This is primarily for passwords that contain symbols that have been swapped around.
```
a5_generator.exe F:\Wordlists\hashmob.net_2025-07-20.found -t .\qwerty-azerty.table -t .\azerty-qwerty.table.
```

From a herbrew to greek substitution with a greek dictionary that can contain partial switches in keyboard halfway through we use: 
```
a5_generator.exe greek-dictionary.txt -t greek-hebrew.table -s
```
Full command example attacking the https://hashmob.net SHA1 left list:
```
a5_generator.exe greek-dictionary.txt -t greek-hebrew.table -s -r -m 1 | hashcat -m 100 .\hashmob.net.100.left -O --bitmap-max 28 -r best66.rule
```

This is an example plain for a greek password transliterated to a hebrew password:
```
6763e527ada91593dfb6e478f5c575849695780a:שמשצשך30
```

## Hex support
As of version 2.0 $HEX[] notation support has been added for both the target and substitution (utf-8). Support uppercase, lowercase and space delimited.
```
euro=$HEX[e282ac]
:P=$HEX[F0 9F 98 9C]
```

## Running the Tool

To run the tool, execute the `main.go` file with the required configuration parameters:
```bash
go mod tidy
go run main.go --table-file path/to/table.txt --dict path/to/dict.txt
```
To compile it:
```bash
go mod tidy
go build -ldflags="-w -s"
./hashcat_a5_table_generator
```
Note: This tool is designed to be efficient and fast. However, the performance may vary depending on the size of the dictionary file and the number of threads used.

## Credits
- T0xlC for research on Transliteration attacks
- Stealthsploit for the idea to replicate a5 table attacks
- TK for requesting to merge the two together

