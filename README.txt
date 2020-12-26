/*******************************************
 *          The Fuzzer                     *
 *          Author: Alexander Zsikla       *
 *          Due Date: 10/28/2020           *
 *******************************************/

* Installation

Run `pip install -r requirements.txt` in order to download 
all of the dependencies

* How to Run

Run `python fuzz.py -l <fuzz_vector_list.txt>`

Optional Parameters

`-o <outputFile.txt>`
`-w <webpage.com>`

* What the Tool is

This is an automated testing tool used by penetration testers 
to detect whether a XSS attack can be performed on a specified webpage.

* How it works

The tool works by taking a list of fuzz vectors (which are javascript strings)
and then does a post/get request to a specified URL with/without a payload.
If the fuzz vector was successfully inserted into the webpage, then
the attack was successful.

* Identifies what has been implemented correctly and what hasn't

I believe to have all of the basic functionality completed as well as:
- Using external fuzzing lists (using the -l flag)
- can test any page for XSS (using the -w flag)

** Note the last one was tested using level 1 from lab 6 and it was pretty cool :) **

* Collaborators

- Andrew Zhang
- Daesob Lim

* Approx hours spent: 5
