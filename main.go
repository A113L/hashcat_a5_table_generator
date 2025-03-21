package main

import (
	"bufio"
	"flag"
	"log"
	"os"
	"runtime"
	"strings"
	"sync"
	"unicode/utf8"
)

// main is the main entry point for the program. It reads the substitution table
// and the wordlist file, then starts a number of goroutines to process the words
// in the wordlist file. The results are written to stdout.
func main() {
	tableFile := flag.String("table-file", "", "Path to substitution table")
	dictFile := flag.String("dict", "", "Path to dictionary file")
	tableMin := flag.Int("table-min", 2, "Minimum password length")
	tableMax := flag.Int("table-max", 15, "Maximum password length")
	threads := flag.Int("threads", runtime.NumCPU(), "Number of threads")
	flag.Parse()

	if *tableFile == "" || *dictFile == "" {
		log.Fatal("Both --table-file and --dict are required")
	}

	substitutionMap, err := readSubstitutionTable(*tableFile)
	if err != nil {
		log.Fatal(err)
	}

	wordlistFile, err := os.Open(*dictFile)
	if err != nil {
		log.Fatal(err)
	}
	defer wordlistFile.Close()

	// Create output channel to print results
	outputChan := make(chan string, 1000)
	var writerWg sync.WaitGroup
	writerWg.Add(1)
	go func() {
		defer writerWg.Done()
		writer := bufio.NewWriter(os.Stdout)
		defer writer.Flush()
		for s := range outputChan {
			writer.WriteString(s + "\n")
		}
	}()

	// Process stuff
	sem := make(chan struct{}, *threads)
	var wg sync.WaitGroup
	scanner := bufio.NewScanner(wordlistFile)
	for scanner.Scan() {
		word := scanner.Text()
		sem <- struct{}{}
		wg.Add(1)
		go func(w string) {
			defer wg.Done()
			defer func() { <-sem }() // Release semaphore when done
			processWord(w, substitutionMap, *tableMin, *tableMax, outputChan)
		}(word)
	}

	wg.Wait()
	close(outputChan)
	writerWg.Wait()
}

// readSubstitutionTable reads a substitution table from a file specified by the given path.
// The table is expected to contain lines in the format "key=value", where both key and value
// are single runes. Lines that are empty or start with '#' are ignored. Each valid substitution
// is added to a map where the key is a rune and the value is a slice of runes representing
// possible substitutions. The function returns this map along with any error encountered
// during the reading process.
func readSubstitutionTable(path string) (map[rune][]rune, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	substitutions := make(map[rune][]rune)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		keyPart, valuePart := parts[0], parts[1]
		if utf8.RuneCountInString(keyPart) != 1 || utf8.RuneCountInString(valuePart) != 1 {
			log.Printf("Invalid substitution line: %q", line)
			continue
		}

		keyRune, _ := utf8.DecodeRuneInString(keyPart)
		valueRune, _ := utf8.DecodeRuneInString(valuePart)
		substitutions[keyRune] = append(substitutions[keyRune], valueRune)
	}
	return substitutions, scanner.Err()
}

// processWord generates all possible variations of the given word by substituting
// runes according to the given substitution map. The generated words are sent on
// the given channel. The generation process is limited to a minimum and maximum
// number of substitutions.
func processWord(word string, subMap map[rune][]rune, minSubstitute, maxSubstitute int, out chan<- string) {
	var generate func(currentWord []rune, currentSubCount, start int)
	generate = func(currentWord []rune, currentSubCount, start int) {
		for i := start; i < len(currentWord); i++ {
			r := currentWord[i]
			if subs, ok := subMap[r]; ok {
				for _, sub := range subs {
					newWord := make([]rune, len(currentWord))
					copy(newWord, currentWord)
					newWord[i] = sub
					newSubCount := currentSubCount + 1

					if newSubCount > maxSubstitute {
						continue
					}

					if newSubCount > minSubstitute {
						out <- string(newWord)
					}

					generate(newWord, newSubCount, i+1)
				}
			}
		}
	}

	generate([]rune(word), 0, 0)
}
