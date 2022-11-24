pandoc --pdf-engine=xelatex -f markdown -t pdf --template=drake.tex $1 > README.pdf
