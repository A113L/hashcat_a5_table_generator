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
* Performing transliteration attacks by substituting q=a w=z (for azerty for example)

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
