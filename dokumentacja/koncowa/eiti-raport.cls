%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%   Simple and elegant academic report    %
%   Copyright by Artur M. Brodzki, 2019   %
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

\ProvidesClass{eiti-raport}

% Load base
\LoadClass[a4paper,12pt]{article}

% Used packages
\RequirePackage{amsfonts}
\RequirePackage{amsmath}
\RequirePackage{amsthm}
\RequirePackage[
	backend=bibtex, 
	bibstyle=ieee
]{biblatex}
\RequirePackage[font=small, labelfont=bf]{caption}
\RequirePackage{fancyhdr}
\RequirePackage{float}
\RequirePackage[T1]{fontenc}
\RequirePackage{fourier}
\RequirePackage[myheadings]{fullpage}
\RequirePackage{graphicx}
\RequirePackage[utf8]{inputenc}
\RequirePackage{lastpage}
\RequirePackage{lipsum}
\RequirePackage{listings}
\RequirePackage[
	protrusion=true, 
	expansion=true
]{microtype}
\RequirePackage{multicol}
\RequirePackage{setspace}
\RequirePackage{sectsty}
\RequirePackage{subcaption}
\RequirePackage{url}
\RequirePackage{wrapfig}
\RequirePackage{xcolor}
\RequirePackage{xkeyval}

% Ddefine and process margin parameter
% Default margin is 2.5 cm
\newcommand\margin{2.5cm}
\define@key{eiti-raport.cls}{margin}[2.5cm]{
	\def\margin{#1}
}
\ExecuteOptionsX{margin}
\ProcessOptionsX
\usepackage[
	a4paper, 
	margin=\margin
]{geometry}

% Initial setup
\onehalfspacing
\setcounter{tocdepth}{5}
\setcounter{secnumdepth}{5}

% Define hyperref colors
\RequirePackage{hyperref}
\hypersetup{
	colorlinks,
	citecolor=black,
	filecolor=black,
	linkcolor=black,
	urlcolor=black
}

% Auxiliary commands and theorems
\newcommand{\HRule}[1]{\rule{\linewidth}{#1}}
\renewcommand\tablename{Tabela}
\newtheorem{theorem}{Twierdzenie}
\newtheorem{definition}{Definicja}
\newtheorem{axiom}{Aksjomat}
\newtheorem{axiom-g}{Aksjomat}
\newtheorem{definition-g}{Definicja}
\newtheorem{theorem-g}{Twierdzenie}
\newtheorem{lemma}{Lemat}
\newtheorem{corollary}{Fakt}

% Author
\renewcommand{\author}[1]{
	\renewcommand{\@author}{#1}
}

% Subject
\newcommand{\subject}[1] {
	\newcommand{\@subject}{#1}
}

% Title page
\let \oldtitle \title
\renewcommand{\title}[1]{
	
	\oldtitle{ 
		\textsc{\@subject} \\
		\HRule{0.5pt} \\
		\LARGE \textbf{\uppercase{#1}
		}
		\HRule{2pt}
	}
	\normalsize
	\sectionfont{\LARGE\scshape}
}


% Header and footer
\pagestyle{fancy}
\fancyhf{}
\setlength\headheight{15pt}
\fancyhead[L]{LALA}

\fancyfoot[C]{\thepage}



% THE END OF INPUT
\endinput
