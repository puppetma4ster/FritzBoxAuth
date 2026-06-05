from pathlib import Path
import typer
from exract import full_extract
from recovery import cracker
app = typer.Typer(invoke_without_command=True)

@app.command()
def extract(out_file: str = typer.Option(
    None,
    "-o",
    "--output",
    help="where to save the extracted hashes",
    exists=False,
    file_okay=True,
    dir_okay=False,
    ),
        in_file: Path = typer.Argument(
            ...,
            help="Input pcapng file",
            exists=True,
            file_okay=True,
            dir_okay=False,
        )

):
    full_extract(in_file, out_file)


@app.command()
def crack(hash_file: Path = typer.Argument(
    ...,
    help="Input extracted hash file",
    exists=True,
    file_okay=True,
    dir_okay=False
),
        wordlist: Path = typer.Option(
            ...,
            "-w",
            "--wordlist",
            help="The wordlist you wanna brute",
            exists=True,
            file_okay=True,
            dir_okay=True
        )
):
    cracker(hash_file, wordlist)




if __name__ == '__main__':
    app()