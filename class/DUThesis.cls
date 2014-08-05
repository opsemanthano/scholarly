%%% ====================================================================
%%%  @LaTeX-class-file{
%%%     filename        = "DUThesis.cls",
%%%     version         = "1.0",
%%%     date            = "9 April 1997",
%%%     writtenby       = "Jonathan Spanier",
%%%     email           = "J.R.Spanier@durham.ac.uk",
%%%     keywords        = "LaTeX, thesis, Durham Thesis",
%%%     docstring       = "This file provides a thesis class for the
%%%                        University of Durham, England."
%%% }

%%%     Based on the following class file....
%%%
%%%     filename        = "unswthesis.cls",
%%%     version         = "1.6a",
%%%     date            = "23 October 1995",
%%%     writtenby       = "John Zaitseff",
%%%     email           = "J.Zaitseff@unsw.edu.au",
%%%     keywords        = "LaTeX, thesis, unsw, unswthesis",
%%%     docstring       = "This file provides a thesis class for the
%%%                        University of New South Wales, Australia."
%%%
%%% ====================================================================

% Things to improve ...
%
% -  \listofabbreviations and \listofsymbols multi-paragraph fixing.
% - Improve LaTeX style - use more LaTeX 2e commands as in class writing guide.
% - Add \qualifications command to print previous degrees you have on your 
%   title page.

% This file provides a thesis class for the School of Engineering
% , University of Durham.  It is meant to be used with LaTeX-2e,
% and exists because of the archaic standards required by universities
% all over the world with regards to thesis styles.
%
% WARNING - WARNING - WARNING - WARNING - WARNING - WARNING - WARNING
%
% This thesis class uses the following packages:-
%
% (1) fancyheadings	(essential)
% (2) draftcopy		(optional and currently inativated [line 155] )
%
%  WARNING - WARNING - WARNING - WARNING - WARNING - WARNING - WARNING
%
% New commands are :-
%
% (1) \listofsymbols
% (2) \listofabbreviations
% (3) \begin{glossary}, \end{glossary} environment (item based) -NOT ACTIVATED
% (4) \begin{abstract}, \end{abstract}
% (5) \begin{acknowledgements}, \end{acknowledgements}
% (6) \begin{dedication}, \end{dedication}
% (7) \copyrightpage
%
% New labels see other documentation.
%
% ==========================================================================
%
% As with all class files, this class is meant to be used as the exclusive
% LaTeX-2e class for the entire document.  It may be introduced in the
% document via:
%
%       \documentclass{DUThesis}
%
% As always, options may be placed before the {DUThesis}.  In this case,
% the following options are supported:
%
%       singlespacing   - Single-space the document (ie, do not apply the
%                         thesis requirements).
%       doublespacing   - Double-space the document (actually, space it
%                         1.21 times the baseline).
%       draft           - Prints the word "DRAFT" across the front page,
%                         as well as on each page (in the footer).
%       final           - Opposite of draft: do not print "DRAFT".
%
%       normal          - Standard (Boring) book presentation. (DEFAULT)
%
%       flash           - Classy presentation style. opposite to normal.
%
% All of the options for the Book class are also supported, namely,
%       10pt, 11pt, 12pt             (11pt is used by default)
%       letterpaper, legalpaper,
%       executivepaper, a4paper,
%       a5paper, b5paper             (a4paper used by default)
%       landscape                    (not used by default)
%       oneside, twoside             (oneside used by default)
%       openright, openany           (openany used by default)
%       onecolumn, twocolumn         (onecolumn used by default)
%       openbib                      (not used by default)
%       leqn, fleqn                  (not used by default)
%

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
\NeedsTeXFormat{LaTeX2e}
\ProvidesClass{DUThesis}%
    [1997/04/09 v1.0 University of Durham Thesis Class]
\typeout{By Jonathan Spanier adapted from many thesis styles}
\RequirePackage{fancyheadings}

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%   Changeable Parameters   %
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% Change these for customisation.  To change them in a LaTeX document,
% simply use \thesisuni{xxx} and \thesisschool{xxx}.

\gdef\@thesisuni{The University of Durham}
\gdef\@thesisschool{School of Engineering}
\gdef\@thesisdegree{Ph.D.}
\gdef\@thesisdegreelong{Doctor of Philosophy}
%\gdef\@thesisschool{School of Electrical Engineering and\\%
%                    Computer Science and Engineering}

% Customise for foreign languages.

\def\supervisorname{Supervisor:}
\def\assessorname{Assessor:}
\def\abstractname{Abstract}

% Copyright year defn.
\def\copyrightyear#1{\gdef\@copyrightyear{#1}}

%%%%%%%%%%%%%%%%%%%%%
%   Class options   %
%%%%%%%%%%%%%%%%%%%%%

\newif\if@dspacing{}
\newif\if@thdraft{}
\newcommand\droptnm{final}

% Extended chapter styles
\newif\if@flash{}

\DeclareOption{singlespacing}{\@dspacingfalse}
\DeclareOption{doublespacing}{\@dspacingtrue}
\DeclareOption{draft}{\@thdrafttrue\renewcommand\droptnm{draft}}
\DeclareOption{final}{\@thdraftfalse\renewcommand\droptnm{final}}
\DeclareOption{normal}{\@flashfalse}
\DeclareOption{flash}{\@flashtrue}
\DeclareOption*{\PassOptionsToClass{\CurrentOption}{book}}
\ExecuteOptions{doublespacing,final,normal}
\ProcessOptions
\LoadClass[a4paper,11pt,oneside,openany,\droptnm]{book}

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%   Draft / final options   %
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% As at Durham we do not have draftcopy.sty
% We do not get draft printed across the front page
% hence the commands below are commented out.

%\if@thdraft%
%    \RequirePackage[first,light]{draftcopy}%
%\fi

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%   Double and single spacing   %
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

\newcommand{\ssp}{%
    \def\baselinestretch{1}%
    \large\normalsize\selectfont}
\newcommand{\dsp}{%
    \def\baselinestretch{1.21}%
    \large\normalsize\selectfont}

% Define conditional:

\if@dspacing%
    \newcommand\s@dsp{\dsp}%
\else%
    \newcommand\s@dsp{\ssp}%
\fi

% Conditional Double-spacing environment

\def\spacing{%
    \begingroup%
    \s@dsp}%
\def\endspacing{%
    \par \vskip \parskip \vskip \baselineskip%
    \endgroup%
    \vskip -\parskip%
    \vskip -\baselineskip}

% Always single-space

\def\sspacing{%
    \begingroup%
    \ssp}%
\def\endsspacing{%
    \par \vskip \parskip \vskip \baselineskip%
    \endgroup%
    \vskip -\parskip%
    \vskip -\baselineskip}

% Execute the following ONLY if double-spacing was selected.

\if@dspacing
    % The following are from "book.cls":
    \renewcommand{\mainmatter}{%
        \cleardoublepage\@mainmattertrue\pagenumbering{arabic}\s@dsp}
    \renewcommand{\backmatter}{%
        \if@openright\cleardoublepage\else\clearpage\fi%
        \@mainmatterfalse\ssp}
    \renewenvironment{figure}[1][tbp]{\@float{figure}[#1]\ssp}{\end@float\s@dsp}
    \renewenvironment{figure*}[1][tbp]{\@dblfloat{figure}[#1]\ssp}{\end@dblfloat\s@dsp}
    \renewenvironment{table}[1][tbp]{\@float{table}[#1]\ssp}{\end@float\s@dsp}
    \renewenvironment{table*}[1][tbp]{\@dblfloat{table}[#1]\ssp}{\end@dblfloat\s@dsp}

    % The following are from "latex.ltx". BUG: This is NOT single-spaced.

    \long\def\@footnotetext#1{\insert\footins{%
        \ssp%                  % Should be single-spaced, but...
        \reset@font\footnotesize
        \interlinepenalty\interfootnotelinepenalty
        \splittopskip\footnotesep
        \splitmaxdepth \dp\strutbox \floatingpenalty \@MM
        \hsize\columnwidth \@parboxrestore
        \protected@edef\@currentlabel{%
            \csname p@footnote\endcsname\@thefnmark
        }%
        \color@begingroup
            \@makefntext{%
                \rule\z@\footnotesep\ignorespaces#1\@finalstrut\strutbox}
        \color@endgroup}}
\fi

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%   Miscellaneous Commands   %
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

\DeclareFontShape{OT1}{cmr}{bx}{sl}{<-> cmbxsl10}{}
\newcommand{\HUGE}{%
    \fontencoding{OT1}\fontfamily{cmr}%
    \fontseries{bx}\fontshape{sl}%
    \fontsize{36}{45}\selectfont}

\newcommand{\thesisuni}[1]{\gdef\@thesisuni{#1}}
\newcommand{\thesisschool}[1]{\gdef\@thesisschool{#1}}
\newcommand{\thesistitle}[1]{\gdef\@thesistitle{#1}}
\newcommand{\thesisauthor}[1]{\gdef\@thesisauthor{#1}}
\newcommand{\thesisdegree}[1]{\gdef\@thesisdegree{#1}}
\newcommand{\thesisdegreelong}[1]{\gdef\@thesisdegreelong{#1}}
\newcommand{\thesisdate}[1]{\gdef\@thesisdate{#1}}
\newcommand{\thesissupervisor}[1]{\gdef\@thesissupervisor{#1}}
\newcommand{\thesisassessor}[1]{\gdef\@thesisassessor{#1}}

\newcommand{\@thesistitle}{\@latex@error{No \noexpand\thesistitle given}\@ehc}
\newcommand{\@thesisauthor}{\@latex@error{No \noexpand\thesisauthor given}\@ehc}
\newcommand{\@thesisdate}{\@latex@error{No \noexpand\thesisdate given}\@ehc}
\newcommand{\@thesissupervisor}{\@latex@error{No \noexpand\thesissupervisor given}\@ehc}
\newcommand{\@thesisassessor}{\@latex@error{No \noexpand\thesisassessor given}\@ehc}

\renewcommand{\title}[1]{\@latex@warning{\noexpand\title is not used with this class}}
\renewcommand{\author}[1]{\@latex@warning{\noexpand\author is not used with this class}}
\renewcommand{\date}[1]{\@latex@warning{\noexpand\date is not used with this class}}

%%%%%%%%%%%%%%%%%%%%%%%%%%
%   Thesis redefinitions %
%%%%%%%%%%%%%%%%%%%%%%%%%%

% Redefine @chapter in book.cls because it really mucks up
% toc, lof and lot generation due to \p@ instead of pt (13/4/97 this is wrong)
% This is very similar to uwthesis.cls

\def\@chapter[#1]#2{
  \ifnum \c@secnumdepth >\m@ne
      \if@mainmatter
         \refstepcounter{chapter}
         \typeout{\@chapapp\space\thechapter.}
         \addcontentsline{toc}{chapter}%
                     {\protect\numberline{\thechapter}#1}
      \else
        \addcontentsline{toc}{chapter}{#1}
      \fi
  \else
    \addcontentsline{toc}{chapter}{#1}
  \fi
  \chaptermark{#1}
  \addtocontents{lof}{\protect\addvspace{10pt}}
  \addtocontents{lot}{\protect\addvspace{10pt}}
  \if@twocolumn
    \@topnewpage[\@makechapterhead{#2}]
  \else
    \@makechapterhead{#2}
    \@afterheading
  \fi
}

% Redefine chapter formating - works with appendix to !!

\if@flash

% \HRule in document would be defined as
% \newcommand{\HRule}{\rule{\linewidth}{1mm}}
%
% However in preamble of LaTeX this can cause serious problems
% with toc lof and lot type files.......

 \def\HRule{\hbox{\vrule\@width \linewidth \@height 1mm \@depth-0pt}}

 \def\@makechapterhead#1{%
  \vspace*{50pt}
  \noindent
  \HRule
  \begin{center}
  \ifnum \c@secnumdepth >\m@ne
   \if@mainmatter
     \mbox{
        \scshape \huge \@chapapp{}}
       \ \normalfont \Huge \thechapter
       \\[20pt]
   \fi
  \fi
  \Huge \bfseries #1
  \end{center}
  \HRule
  \vspace*{40pt}
 }

 \def\@makeschapterhead#1{%
  \vspace*{50pt}
  \noindent
  \HRule
  \begin{center}
  \normalfont \Huge \bfseries #1
  \end{center}
  \HRule
  \vspace*{40pt}
 }
\else
 \def\@makechapterhead#1{%
   \vspace*{50\p@}%
     {\parindent \z@ \raggedright \normalfont
       \ifnum \c@secnumdepth >\m@ne
          \huge\bfseries \@chapapp{} \thechapter
          \par\nobreak
          \vskip 20\p@
       \fi
   \interlinepenalty\@M
   \Huge \bfseries #1\par\nobreak
   \vskip 40\p@
  }}

 \def\@makeschapterhead#1{%
   \vspace*{50\p@}%
     {\parindent \z@ \raggedright
      \normalfont
      \interlinepenalty\@M
      \Huge \bfseries  #1\par\nobreak
      \vskip 40\p@
     }}
\fi

% Miscell... get \listofstuff to put themselves into contents...

% Grabbed from book.cls file

\renewcommand{\listoffigures}{%
    \if@twocolumn
      \@restonecoltrue\onecolumn
    \else
      \@restonecolfalse
    \fi
    \chapter*{\listfigurename
      \@mkboth{\MakeUppercase\listfigurename}%
              {\MakeUppercase\listfigurename}}%
% Additions here ..
    \addcontentsline{toc}{chapter}{\listfigurename}%
%
    \@starttoc{lof}%
    \if@restonecol\twocolumn\fi
    }

\renewcommand{\listoftables}{%
    \if@twocolumn
      \@restonecoltrue\onecolumn
    \else
      \@restonecolfalse
    \fi
    \chapter*{\listtablename
      \@mkboth{%
          \MakeUppercase\listtablename}{\MakeUppercase\listtablename}}%
% Additions here..
    \addcontentsline{toc}{chapter}{\listtablename}%
%
    \@starttoc{lot}%
    \if@restonecol\twocolumn\fi
    }

% List of symbols and list of abbreviations are modified
% versions from afthesis.cls
%
% The original idea was to use the index (actually glossary) commands
% and run output through makeindex to give a sorted output.
% However, makeindex program will format the files wrongly,
% hence the table of contents way and then recompute the elements
% using UNIX sort.

% The set up for \symbol and \abbreviation WILL automatically type
% set the symbol / abbreviation name INTO the text.

% new definition to allow symbols and abbreviations to have no
% page formating in there environments

\def\addnewcontentsline#1#2#3#4{%
   \addtocontents{#1}{\protect\contentsline{#2}{#3}{#4}}}

% symbol and abbreviation formatting style using \l@DUTspecial
% I was going to implement plain.tex version of itemize using
% \hangident and \hangafter, but gave up and used the general purpise
% \parshape instead.
%
% Cannot use multiple paragraphs in the second element of the \symbol
% or \abbreviation command. i.e. if \symbol{#1}{#2}, the #2 parameter
% will cause the following TeX ERROR ...
%
% ! Paragraph ended before \@symboldef was complete.
% <to be read again> 
%                  \par 
% l.147 
%
% Incidentally the #1 parameter is meant to be ONLY a keyword - so if this
% was a paragraph, then LaTeX would complain again !!

\newlength{\DUTlen}		% Length of symbol/abbrev name in correct font
\newlength{\DUTmag}		% shift either side of center
\newlength{\DUTparwidth}	% Total length for typsetting

\newcommand*\l@DUTspecial[2]{
	\settowidth{\DUTlen}{\Large #1}
	\DUTmag 2em			% Ideally this should be global !!
	\DUTparwidth 0.5\linewidth	% Ideally this should be global !!
	\advance\DUTparwidth -\DUTmag	% So we have a reasonable right margin.
	\@tempdima 0.5\linewidth	% Name flushed right.
	\advance\@tempdima -\DUTmag
	\advance\@tempdima -\DUTlen
	\@tempdimb 0.5\linewidth	% 2nd/inf paragraph start
	\advance\@tempdimb \DUTmag
	\@tempdimc \DUTparwidth		% Extend initial par. length
	\advance\@tempdimc 2\DUTmag
	\advance\@tempdimc \DUTlen
	\parskip 10pt
	\parindent \z@\relax		% zero out paragraph indent
	\parshape 2 \@tempdima \@tempdimc \@tempdimb \DUTparwidth
	{\Large {#1}}\ignorespaces \hskip 2\DUTmag {\Large {#2}} \par
}

\newcommand\listsymbolname{List of Symbols}
\def\listofsymbols{%
    \if@twocolumn
      \@restonecoltrue\onecolumn
    \else
      \@restonecolfalse
    \fi
    \chapter*{\listsymbolname
      \@mkboth{%
          \MakeUppercase\listsymbolname}{\MakeUppercase\listsymbolname}}%
% Additions here..
    \addcontentsline{toc}{chapter}{\listsymbolname}%
%
    \@starttoc{los}%
    \if@restonecol\twocolumn\fi
    }

% add symbol to los and in text with optional definition in the los
% \def\symbol{\@ifnextchar[{\@symboldef}{\@symbolnodef}}
% \def\@symboldef[#1]#2{#2\addnewcontentsline{los}{DUTspecial}{#2}{#1}}
% \def\@symbolnodef#1{#1\addcontentsline{los}{DUTspecial}{#1}}

\def\symbol{\@symboldef}
\def\@symboldef#1#2{#1\addnewcontentsline{los}{DUTspecial}{#1}{#2}}

% LIST OF ABBREVIATIONS
%
\newcommand\listabbrevename{List of Abbreviations}
 
\def\listofabbreviations{%
    \if@twocolumn
      \@restonecoltrue\onecolumn
    \else
      \@restonecolfalse
    \fi
    \chapter*{\listabbrevename
      \@mkboth{% 
          \MakeUppercase\listabbrevename}{\MakeUppercase\listabbrevename}}%
% Additions here..
    \addcontentsline{toc}{chapter}{\listabbrevename}%
%
    \@starttoc{loa}% 
    \if@restonecol\twocolumn\fi  
    } 

     
% add abbreviation to loa and in text with optional definition in the loa
% \def\abbreviation{\@ifnextchar[{\@abbreviationdef}{\@abbreviationnodef}}
% \def\@abbreviationdef[#1]#2{#2\addnewcontentsline{loa}{DUTspecial}{#2}{#1}}
% \def\@abbreviationnodef#1{#1\addcontentsline{loa}{DUTspecial}{#1}}

 \def\abbreviation{\@abbreviationdef}
 \def\@abbreviationdef#1#2{#1\addnewcontentsline{loa}{DUTspecial}{#1}{#2}}

%%%%%%%%%%%%%%%%%%%%%%%%%%%
%   Thesis front matter   %
%%%%%%%%%%%%%%%%%%%%%%%%%%%

% Title page

\renewcommand{\maketitle}%
    {\begin{titlepage}%
        \null\vfil
        \begin{center}%
            {\huge \scshape \@thesisuni \par}%
            \vskip 2em%
            {\Large \scshape \@thesisschool \par}%
            \vskip 7em%
            {\HUGE \@thesistitle \par}%
            \vskip 6em%
            {\Large \bfseries \@thesisauthor \par}%
            \vskip .7em%
%           {\large \@thesisdegree \par}%
%           \vskip .7em%
%           {\large \@thesisdate \par}%
%           \vskip 8em%
%           {\large \textsl{\supervisorname}\ \@thesissupervisor \par}%
%           {\large \textsl{\assessorname}\ \@thesisassessor \par}%
        \end{center}\par
  \vfill
     \begin{center}
       \sc\sloppy
        \begin{minipage}{3in}
        \sloppy
        A thesis submitted in partial fulfillment of the requirements of the Council of the \@thesisuni \  for the degree of \@thesisdegreelong \  (\@thesisdegree).
        \end{minipage}
        \\[2ex]
        \@thesisdate
      \end{center}
%        \vskip 30\p@
        \vfil\null
    \end{titlepage}%
    \setcounter{footnote}{0}%
    \let\maketitle\relax}

% Abstract environment (not defined by "book.cls")

\newenvironment{abstract}{%
    \titlepage
% More mods
    \begin{center}
    {\large \@thesistitle \par}
    {\large \@thesisauthor  \par}
    {\large \@thesisdegree \hspace*{2pt} \@copyrightyear \par}
    \end{center}
    \vspace*{1.0cm}
%
    \null\vfil
    \begin{center}%
        {\Large \bfseries \abstractname}
        \@endparpenalty\@M
    \end{center}\spacing}%
    {\endspacing\par\vfil\null\endtitlepage}

% Define copyright page
% pinched from a previous duthesis.sty and signature line from suthesis.sty
% and uwthesis.cls (more human readable form than suthesis.sty)
% and mitthesis.sty for \dotfill

\newcommand{\copyrightpage}{%
\vspace*{1.0cm}
\thispagestyle{empty}
\begin{center}
{\huge \bfseries Declaration} \\[1.0cm]
\end{center}
\par\smallskip\noindent
I hereby declare that this thesis is a record of work undertaken by myself,
that it has not been the subject of any previous appplication for a degree, and
that all sources of information have been duly acknowledged.

% This is from suthesis.sty
%\begin{center}
%\vspace{2.5in}
%\hbox to 4in{\hfil\shortstack{\vrule width 3in height 0.4pt}}
%\end{center}

% This is from duthesis.sty

%\begin{flushright}
%\@thesisauthor, \@thesisdate \\
%\end{flushright}

\begin{flushright}
        \vspace{.5in}
        \makebox[3.5in]{\dotfill} % \\ \@thesisauthor, \@thesisdate}
        \\
        \vspace{5ex}
        \@thesisauthor, \@thesisdate
\end{flushright}
        \null\vfill
        \begin{center}
                \bf   \copyright\ Copyright \@copyrightyear,
                \@thesisauthor\\
        \end{center}
\medskip
The copyright of this thesis rests with the author.  No quotation from it
should be published without the written consent of the copyright owner,
and information derived from it should be acknowledged.

\vfill
\newpage
}

% Ideas from uwthesis.cls
% Acknowledgement environment

\newenvironment{acknowledgements}{%
    \titlepage
    \vspace*{1.0cm}
    \begin{center}%
        {\huge \bfseries Acknowledgments} \\[1.0cm]
        \@endparpenalty\@M
    \end{center}\spacing}%
    {\endspacing\par\vfil\null\endtitlepage}

% Dedication environment

\newenvironment{dedication}{%
        \titlepage
        \vspace*{1.0cm}
        \begin{center}
                {\huge \bfseries Dedication} \\[1.0cm]
                \@endparpenalty\@M
        \end{center}
        \spacing}%
        {\endspacing\par\vfil\null\endtitlepage}

% glossary environment (from uwthesis)
% version formats nicely as we are using the Ventry environment
% as found on page 63 of the LaTeX companion (May 1994)
%
% THIS IS NOW NOT REQUIRED AND HENCE COMMENTED OUT WITH "%%"
%%
%%\renewenvironment{glossary}[1][\qquad]%
%%  {\if@twocolumn
%%      \@restonecoltrue\onecolumn
%%    \else
%%      \@restonecolfalse
%%    \fi
%%    \chapter*{List of Abbreviations
%%      \@mkboth{\MakeUppercase {List of Abbreviations}}%
%%              {\MakeUppercase {List of Abbreviations}}}%
%%    \addcontentsline{toc}{chapter}{List of Abbreviations}
%%    \begin{list}{}%
%%     {\renewcommand{\makelabel}[1]{\uppercase{##1:}\hfill}%
%%       \settowidth{\labelwidth}{\uppercase{#1:}}%
%%       \setlength{\leftmargin}{\labelwidth}
%%       \addtolength{\leftmargin}{\labelsep}
%
% Arithmetic is anoying in LaTeX without calc package as this environment shows
% The alternative would be to use TeX constructs....
% This was proved to be very anoying as I got the description wrong !!
% See The LaTeX Companion (page 64)
%%    }% End of initial list declarations
%%  }  % End of glosary environment (begin part)
%%  {\end{list}
%%    \if@restonecol\twocolumn\fi
%%  }

% Redefine bibliography -
%                       - First redefine \bibname
%                       - second redefine bibliography environment
%                         ( this is the same as the book.cls EXCEPT
%                           the contents is updated )
\renewcommand{\bibname}{References}

\renewenvironment{thebibliography}[1]
     {\chapter*{\bibname
        \@mkboth{\MakeUppercase\bibname}{\MakeUppercase\bibname}}%
      \addcontentsline{toc}{chapter}{\bibname}
      \list{\@biblabel{\@arabic\c@enumiv}}%
           {\settowidth\labelwidth{\@biblabel{#1}}%
            \leftmargin\labelwidth
            \advance\leftmargin\labelsep
            \@openbib@code
            \usecounter{enumiv}%
            \let\p@enumiv\@empty
            \renewcommand\theenumiv{\@arabic\c@enumiv}}%
      \sloppy   
      \clubpenalty4000
      \@clubpenalty \clubpenalty
      \widowpenalty4000%
      \sfcode`\.\@m}
     {\def\@noitemerr
       {\@latex@warning{Empty `thebibliography' environment}}%
      \endlist}



%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%   General Page Parameters   %
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% The university requirements specify a 25mm border all around, except for
% the bottom (20mm). We actually increase this to make it more
% typographically correct. The page dimensions used were taken from "The
% LaTeX Companion", p. 85, with appropriate modifications.

% all parameters in <number>\p@ are in point format
% The scale is 1 point = 0.351 mm = 1/72.27 in
%              1 inch  =  25.4 mm = 72.27 pt
%              1 math unit (18 mu = 1 em)
%              em is width of M in current font
%              ex is height of a small x in the current font

% Durham University Requirements have 20 mm border all round and a
% left-hand margin 0f 40 mm for binding

%\setlength\oddsidemargin{15\p@}
%\setlength\evensidemargin{15\p@}
% original unswthesis.cls
%\setlength\oddsidemargin{30\p@}
%\setlength\evensidemargin{30\p@}
% updated for durham - 40 mm left margin for binding
\setlength\oddsidemargin{42\p@}
\setlength\evensidemargin{42\p@}
%
\setlength\topmargin{15\p@}
\setlength\headsep{20\p@}
\setlength\headheight{20\p@}
%\setlength\footskip{40\p@}
\setlength\marginparwidth{15\p@}
\setlength\marginparsep{\z@}
\setlength\textwidth{\paperwidth %
    \advance\textwidth -144\p@ %
    \advance\textwidth -\oddsidemargin %
    \advance\textwidth -\marginparwidth %
    \advance\textwidth -\marginparsep}
\setlength\textheight{\paperheight %
    \advance\textheight -140\p@ %
    \advance\textheight -\topmargin %
    \advance\textheight -\headheight %
    \advance\textheight -\headsep %
    \advance\textheight -\footskip}

% Page headings and footers.

\pagestyle{fancyplain}
\renewcommand{\chaptermark}[1]{\markboth{\thechapter. #1}{\thechapter. #1}}

% The line below this comment uses the uppercase command to do what is says !!
%\renewcommand{\chaptermark}[1]{\markboth{\thechapter. \uppercase{#1}}{\thechapter. \uppercase{#1}}}

% To get chapter name as in "Chapter" we use \chaptername

% The line below this comment will print the chapter name when \<sone>mark
% is activated in the fancyheading headers and/or footers
%\renewcommand{\chaptermark}[1]{\markboth{#1}{#1}}

\renewcommand{\sectionmark}[1]{}

% line at bottom as well
\setlength{\footrulewidth}{0.4pt}
\setlength{\plainfootrulewidth}{0.4pt}
%

\lhead[\fancyplain{}{\bfseries\thepage}]{\fancyplain{}{\bfseries\rightmark}}
\rhead[\fancyplain{}{\bfseries\leftmark}]{\fancyplain{}{\bfseries\thepage}}
\cfoot{\fancyplain{\textrm{\thepage}}{}}

% Definitions as found in Martin Bradley's Thesis

%\lhead{\fancyplain{}{\slseries\leftmark}}
%\chead{}
%\rhead{}
%\lfoot{}
%\cfoot{\textrm\thepage}
%\rfoot{}

%

\if@thdraft
    \rfoot[\textbf{Draft:}~\today]{}
    \lfoot[]{\textbf{Draft:}~\today}
\fi
