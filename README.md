# The Fuzzer
## Author: Alexander Zsikla

### Installation

Run `pip install -r requirements.txt` in order to download 
all of the dependencies

### How to Run

Run `python fuzz.py -l <fuzz_vectors.txt>`

Optional Parameters

`-o <outputFile.txt>`
`-w <webpage.com>`

### What the Tool is

This is an automated testing tool used by penetration testers 
to detect whether a XSS attack can be performed on a specified webpage.

### How it works

The tool works by taking a list of fuzz vectors (which are javascript strings)
and then does a post/get request to a specified URL with/without a payload.
If the fuzz vector was successfully inserted into the webpage, then
the attack was successful.

