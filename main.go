package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/alecthomas/kong"
)

// CLI defines the command-line interface structure
type CLI struct {
	DictFile      string   `arg:"" help:"Path to dictionary file"`
	TableFiles    []string `help:"Path to substitution table (multiple possible, sequential)" required:"" short:"t"`
	TableMin      int      `help:"Minimum substitutions" default:"0" short:"m"`
	TableMax      int      `help:"Maximum substitutions" default:"15" short:"x"`
	Threads       int      `help:"Number of threads" default:"-1"`
	SubstituteAll bool     `help:"Substitution Cipher, see Transliteration Attack" short:"s"`
	ReverseSub    bool     `help:"Reverse substitution direction" short:"r"`
}

func main() {
	var cli CLI
	ctx := kong.Parse(&cli,
		kong.Name("a5_generator"),
		kong.Description("Generates word variations based on a substitution table. v0.2"),
		kong.UsageOnError(),
	)

	if cli.Threads == -1 {
		cli.Threads = runtime.NumCPU()
	}

	substitutionMap := make(map[string][]string)
	for _, tableFile := range cli.TableFiles {
		tableMap, err := readSubstitutionTable(tableFile)
		if err != nil {
			log.Fatal(err)
		}

		for key, values := range tableMap {
			substitutionMap[key] = append(substitutionMap[key], values...)
		}
	}

	wordlistFile, err := os.Open(cli.DictFile)
	if err != nil {
		log.Fatal(err)
	}
	defer wordlistFile.Close()

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

	sem := make(chan struct{}, cli.Threads)
	var wg sync.WaitGroup
	scanner := bufio.NewScanner(wordlistFile)
	for scanner.Scan() {
		word := scanner.Text()
		sem <- struct{}{}
		wg.Add(1)
		go func(password string) {
			defer wg.Done()
			defer func() { <-sem }()
			if cli.SubstituteAll {
				if cli.ReverseSub {
					processWordSubstituteAllReverse(password, substitutionMap, cli.TableMin, cli.TableMax, outputChan)
				} else {
					processWordSubstituteAll(password, substitutionMap, cli.TableMin, cli.TableMax, outputChan)
				}
			} else {
				if cli.ReverseSub {
					processWordReverse(password, substitutionMap, cli.TableMin, cli.TableMax, outputChan)
				} else {
					processWord(password, substitutionMap, cli.TableMin, cli.TableMax, outputChan)
				}
			}
		}(word)
	}

	wg.Wait()
	close(outputChan)
	writerWg.Wait()
	ctx.Exit(0)
}

// readSubstitutionTable reads a substitution table from a file specified by the given path.
// The table is expected to contain lines in the format "key=value", where both key and value
// are single runes. Lines that are empty or start with '#' are ignored. Each valid substitution
// is added to a map where the key is a rune and the value is a slice of runes representing
// possible substitutions. The function returns this map along with any error encountered
// during the reading process. This support $HEX[] notation on both sides and is also required to substitute =
func readSubstitutionTable(path string) (map[string][]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	substitutions := make(map[string][]string)
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
		decodedKey, err := decodeHexNotation(keyPart)
		if err != nil {
			log.Printf("Error decoding hex notation in key: %q - %v", line, err)
			continue
		}

		decodedValue, err := decodeHexNotation(valuePart)
		if err != nil {
			log.Printf("Error decoding hex notation in value: %q - %v", line, err)
			continue
		}

		substitutions[decodedKey] = append(substitutions[decodedKey], decodedValue)
	}
	return substitutions, scanner.Err()
}

// decodeHexNotation decodes the hashcat HEX notation to their respective bytes
func decodeHexNotation(value string) (string, error) {
	// Check if value starts with $HEX[ and ends with ]
	if len(value) < 7 || !strings.HasPrefix(value, "$HEX[") || !strings.HasSuffix(value, "]") {
		return value, nil // Not a hex notation, return as-is
	}

	// Extract the hex string between $HEX[ and ]
	hexStr := value[5 : len(value)-1]
	hexStr = strings.ReplaceAll(hexStr, " ", "")

	decodedBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return "", fmt.Errorf("invalid hex string %q: %v", hexStr, err)
	}
	return string(decodedBytes), nil
}

// processWord generates all possible variations of the given word by substituting
// runes according to the given substitution map. The generated words are sent on
// the given channel. The generation process is limited to a minimum and maximum
// number of substitutions.
func processWord(word string, subMap map[string][]string, minSubstitute, maxSubstitute int, out chan<- string) {
	if minSubstitute == 0 {
		minSubstitute += 1
	}

	var generate func(currentWord string, currentSubCount, start int)
	generate = func(currentWord string, currentSubCount, start int) {
		for i := start; i < len(currentWord); i++ {
			// Try all possible key lengths from longest to shortest
			for keyLength := len(currentWord) - i; keyLength >= 1; keyLength-- {
				if i+keyLength > len(currentWord) {
					continue
				}

				key := currentWord[i : i+keyLength]
				if subs, ok := subMap[key]; ok {
					for _, sub := range subs {
						newWord := currentWord[:i] + sub + currentWord[i+keyLength:]
						newSubCount := currentSubCount + 1

						if newSubCount > maxSubstitute {
							continue
						}

						if newSubCount >= minSubstitute {
							out <- newWord
						}

						// Skip past the substituted part to avoid overlapping substitutions
						generate(newWord, newSubCount, i+len(sub))
					}
				}
			}
		}
	}

	generate(word, 0, 0)
}

// processWordReverse generates variations starting from maximum substitutions down to minimum
func processWordReverse(word string, subMap map[string][]string, minSubstitute, maxSubstitute int, out chan<- string) {
	// Find all possible substitution positions
	var positions []struct {
		start, keyLength int
		subs             []string
	}

	for i := 0; i < len(word); i++ {
		for keyLength := 1; keyLength <= len(word)-i; keyLength++ {
			key := word[i : i+keyLength]
			if subs, ok := subMap[key]; ok {
				positions = append(positions, struct {
					start, keyLength int
					subs             []string
				}{i, keyLength, subs})
			}
		}
	}

	totalPossible := len(positions)
	if totalPossible < minSubstitute {
		return
	}

	actualMax := maxSubstitute
	if actualMax > totalPossible {
		actualMax = totalPossible
	}

	// Generate combinations from max down to min
	for subCount := actualMax; subCount >= minSubstitute; subCount-- {
		// Generate all combinations of 'subCount' substitutions
		combinations := generateCombinations(len(positions), subCount)

		for _, combo := range combinations {
			// Check if substitutions overlap
			if !validSubstitutionPositions(combo, positions) {
				continue
			}

			// Apply first substitution option for each position
			result := word
			offset := 0
			for _, idx := range combo {
				pos := positions[idx]
				sub := pos.subs[0]
				actualStart := pos.start + offset
				result = result[:actualStart] + sub + result[actualStart+pos.keyLength:]
				offset += len(sub) - pos.keyLength
			}
			out <- result
		}
	}
}

func generateCombinations(n, k int) [][]int {
	if k == 0 {
		return [][]int{{}}
	}
	if n < k {
		return nil
	}

	var result [][]int
	// Recursive combination generation
	for i := n - 1; i >= k-1; i-- {
		subCombos := generateCombinations(i, k-1)
		for _, sub := range subCombos {
			combo := append([]int{i}, sub...)
			result = append(result, combo)
		}
	}
	return result
}

func validSubstitutionPositions(combo []int, positions []struct {
	start, keyLength int
	subs             []string
}) bool {
	// Check if any substitutions overlap
	intervals := make([][2]int, len(combo))
	for i, idx := range combo {
		pos := positions[idx]
		intervals[i] = [2]int{pos.start, pos.start + pos.keyLength - 1}
	}

	// Sort intervals by start position
	sort.Slice(intervals, func(i, j int) bool {
		return intervals[i][0] < intervals[j][0]
	})

	for i := 1; i < len(intervals); i++ {
		if intervals[i][0] <= intervals[i-1][1] {
			return false
		}
	}
	return true
}

// processWordSubstituteAll generates variations by replacing all occurrences of each substituted character.
func processWordSubstituteAll(word string, subMap map[string][]string, minSubstitute, maxSubstitute int, out chan<- string) {
	// Find all unique substitutable patterns in the word
	uniquePatterns := make(map[string]bool)

	// Scan through the word to find all possible substitution patterns
	for i := 0; i < len(word); i++ {
		for pattern := range subMap {
			if i+len(pattern) <= len(word) && word[i:i+len(pattern)] == pattern {
				uniquePatterns[pattern] = true
			}
		}
	}

	// Convert to slice for deterministic processing
	patterns := make([]string, 0, len(uniquePatterns))
	for pattern := range uniquePatterns {
		patterns = append(patterns, pattern)
	}
	sort.Strings(patterns) // Ensure deterministic order

	// Generate all possible combinations of substitutions
	var generate func(currentSubs map[string]string, pos int)
	generate = func(currentSubs map[string]string, pos int) {
		if pos >= len(patterns) {
			subCount := len(currentSubs)
			if subCount < minSubstitute || subCount > maxSubstitute {
				return
			}

			// Apply substitutions to all occurrences
			result := word
			for pattern, replacement := range currentSubs {
				result = strings.ReplaceAll(result, pattern, replacement)
			}
			out <- result
			return
		}

		currentPattern := patterns[pos]

		// For each possible substitution of this pattern
		for _, sub := range subMap[currentPattern] {
			// Create a new substitution map for this branch
			newSubs := make(map[string]string, len(currentSubs)+1)
			for k, v := range currentSubs {
				newSubs[k] = v
			}
			newSubs[currentPattern] = sub
			generate(newSubs, pos+1)
		}

		// Also generate the case where we don't substitute this pattern
		generate(currentSubs, pos+1)
	}

	// Start with empty substitution map
	generate(make(map[string]string), 0)
}

// processWordSubstituteAllReverse generates variations by starting with all substitutions
// and progressively removing them down to the minimum count
func processWordSubstituteAllReverse(word string, subMap map[string][]string, minSubstitute, maxSubstitute int, out chan<- string) {
	// Find all unique substitutable patterns in the word
	uniquePatterns := make(map[string]bool)

	for i := 0; i < len(word); i++ {
		for pattern := range subMap {
			if i+len(pattern) <= len(word) && word[i:i+len(pattern)] == pattern {
				uniquePatterns[pattern] = true
			}
		}
	}

	patterns := make([]string, 0, len(uniquePatterns))
	for pattern := range uniquePatterns {
		patterns = append(patterns, pattern)
	}
	sort.Strings(patterns)

	totalPossible := len(patterns)
	if totalPossible < minSubstitute {
		return
	}

	// Start with all possible substitutions (using first substitution option for each)
	allSubs := make(map[string]string)
	for _, pattern := range patterns {
		if subs, ok := subMap[pattern]; ok && len(subs) > 0 {
			allSubs[pattern] = subs[0] // Use first substitution option
		}
	}

	// Generate all subsets from maximum down to minimum
	var generateSubsets func(currentSubs map[string]string, pos int)
	generateSubsets = func(currentSubs map[string]string, pos int) {
		currentCount := len(currentSubs)
		if currentCount < minSubstitute {
			return
		}

		if currentCount <= maxSubstitute {
			// Apply substitutions to all occurrences
			result := word
			for pattern, replacement := range currentSubs {
				result = strings.ReplaceAll(result, pattern, replacement)
			}
			out <- string(result)
		}

		// Skip if we've reached the minimum
		if currentCount <= minSubstitute {
			return
		}

		// Generate all possible subsets with one less substitution
		for i := pos; i < len(patterns); i++ {
			pattern := patterns[i]
			if _, exists := currentSubs[pattern]; !exists {
				continue
			}

			newSubs := make(map[string]string, len(currentSubs)-1)
			for k, v := range currentSubs {
				if k != pattern {
					newSubs[k] = v
				}
			}
			generateSubsets(newSubs, i+1)
		}
	}

	generateSubsets(allSubs, 0)
}
