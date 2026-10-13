# The 30-second check of the report's first page (Q6.1, #74)

The monthly report is what an MSP hands to a customer or an auditor. Its first page has to
tell a person who is not technical, in under 30 seconds, whether the backups passed. Q6.1's
third step is to find out whether it does, with a real person. This file is the method, and
the result once the check has been done. Nothing here is a test the code runs: a person reads,
a person times, a person writes down what happened.

## What to hand over

Page 1 of `docs/api/cloud-lab/c6.4-sample-report.pdf` as a single-page PDF, printed or on a
screen, with nothing else of the report. The page is made outside the repository (it is the
sample's own first page, nothing new) with pypdf, from `cloud/`:

```powershell
uv run python -c "from pypdf import PdfReader, PdfWriter; r = PdfReader('../docs/api/cloud-lab/c6.4-sample-report.pdf'); w = PdfWriter(); w.add_page(r.pages[0]); w.write('%LOCALAPPDATA%/RestoreProof/lab/q6.1-page1.pdf'.replace('%LOCALAPPDATA%', __import__('os').environ['LOCALAPPDATA']))"
```

The file lands at `%LOCALAPPDATA%\RestoreProof\lab\q6.1-page1.pdf`. Give the reader the page
alone: not the file name, not this document, not the other pages.

## Who

One person who does not work in IT and has not seen the report before. A friend or a family
member is fine. They need no knowledge of backups; the page has to carry its own meaning.

## The question

Say exactly this, and nothing more, as you hand the page over:

> "Please read this. Tell me when you can answer: did the backups pass?"

Do not say what the page is, what a backup is, what a test is, or where to look. Do not point.
If the reader asks a question, say "whatever you can tell from the page" and write the
question down. Do not answer it until the check is over.

## Timing

Start the clock when the page is in the reader's hands (or on their screen). Stop it at the
first answer to the question, in whatever words the reader uses. Thirty seconds is the target.
A reader who is still reading at 60 seconds is asked "what do you think so far?", the clock
stopped there, and the answer recorded as given at 60 seconds or more.

## The expected answer

The sample's page 1 says "1 of 5 tests failed" and "1 of 5 tests could not run (error)". So
the right answer is **"not all passed"**: one failed, one could not run, and the others
passed. An answer of "no" or "some failed" or "one failed" is right. An answer of "yes, they
passed" is wrong, and is recorded as wrong; it means the page let the reader miss the failure,
which is the fault the check exists to find. "I can't tell" is recorded as given.

## What to write down

In the Result section below, in this order:

1. The date, and who read (first name or "a friend"; no surname, no address).
2. How the page was shown (paper or screen, and the screen's size if a screen).
3. The time, in seconds, from the page in their hands to the first answer.
4. The answer, in the reader's own words, verbatim.
5. Whether that answer is right by the rule above (right / wrong / could not tell).
6. Every question the reader asked and every place they said they were confused, verbatim,
   with the time it was asked.
7. Anything the reader said afterwards about the page, when told what it was.

Record what happened, not what should have happened. A wrong answer or a slow one is the
useful result; it is the reason to change the page, and the change is a task of its own.

## Result

**Not yet done.** This section is empty until the owner has run the check with one reader and
recorded the seven items above. The issue #74 stays open until then.
