## About
A python script to verify email authentication methods from an `.eml` file. Checks for SPF and DKIM alignments and whether those methods passed. Helpful in detecting spoofed emails. Follows RFC guidelines 7208, 6376, 7489, 822 and 1123.

## Last Still(s)
![SPF.png](https://raw.githubusercontent.com/nisargsuthar/Emmy/main/images/spf.png?)
![DKIM1.png](https://raw.githubusercontent.com/nisargsuthar/Emmy/main/images/dkim1.png?)
![DKIM2.png](https://raw.githubusercontent.com/nisargsuthar/Emmy/main/images/dkim2.png?)
![DMARC.png](https://raw.githubusercontent.com/nisargsuthar/Emmy/main/images/dmarc.png?)

## Disclaimer
This script still doesn't parse the email bodies of all samples correctly due to some errors in how the body canonicalization algorithm is implemented.

## Installation
**Step 1**: Create a virtual environment using:
```python
python.exe -m venv emmy
```

**Step 2**: Depending on your OS, activate the virtual environment using:
* Windows: `.\emmy\Scripts\activate`
* Linux: `source emmy/Scripts/activate`

**Step 3**: Install requirements using:
```python
pip install -r requirements.txt
```