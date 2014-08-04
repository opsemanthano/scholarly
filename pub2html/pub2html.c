#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/signal.h>
#include <ufs/quota.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/wait.h>

/* Quotas defines */

#define QUOTACAPELLA "/dev/sd3c"
#define QUOTATALLIS "/dev/sd2c"
#define SHARED_ID 40005
#define SHARED_GROUP 1350

/* quota accounts and which machine is capella ? */

#define IS_CAPELLA	"capella"

/* httpd server and html generation defines */

#define SRM_CONF "/usr/local/etc/httpd/conf/srm.conf"
#define PUB2HTML "/usr/local/etc/httpd/pub2html/"
#define PROTECT  ".protect"
#define WHO	".protect.who"
#define MAX_HTML_SCRIPT_LENGTH 256
#define MAX_LENGTH	256
#define VALID_USERS 17			/* 20 Aliases with 3 taken */
					/* One alias is for the publications. */
#define USER_SIZE 12			/* 7 characters is max. for usernames */

/* System commands and path for each command */

#define COPY		"/usr/bin/cp"
#define MOVE		"/usr/bin/mv"
#define COMPRESS	"/usr/ucb/compress"
#define GZIP		"/usr/local/bin/gzip"

#define LOGNAME		"LOGNAME"	/* Environment variable */

#define NUM_ARGS	7		/* No. of arguments for execvp */


/* defines for cfg_ subroutines */

#define LF	10
#define CR	13

/* Function declarations */

#ifdef __STRICT_ANSI__

/* This works for gnu c/c++ only */

int  parse_srm_file( char* );
void cfg_getword( char*, char* );
int  cfg_getline( char*, int, FILE* );
int  pub_quota( char*, int );

#endif

/* global variables */

char sccsid[] = "@(#)pub2html v1.00 - Copyright : Durham University - J.R. Spanier 1995";
char publoc[MAX_LENGTH];

/* Main program starts */

int main(argc, argv)
int argc;
char *argv[];
{

 char inputfilename[MAX_LENGTH];
 char outputfilename[MAX_LENGTH];
 char anotherfilename[MAX_LENGTH];
 char path[MAX_LENGTH];
 char *what[NUM_ARGS];
 char reflabel[10];
 char *hostname;
 char *otherpoint;
 char logname[USER_SIZE];
 char select;
 char c;

 char *execargv[NUM_ARGS];	/* execlp argv pointer to what */

#ifdef SYSV 
 pid_t pid;		/* process ID of the child */
#else
 int   pid;             /* process ID of the child */
#endif

 int fd;		/* file descriptor for locking */
 FILE *in, *out;	/* file pointers for accessing */

 strcpy(reflabel,"-l");	/* Default to generate labels */
 select = 'G';		/* Default compression program */

 while(--argc > 0 && (*++argv)[0] == '-')
	while (c = *++argv[0] )
		switch(c) {
			case 'o':
				 strcpy(reflabel,"");
				 break;

			case 'c':
				 select='Z';
				 break;

			case 'g':
				 select='G';
				 break;
			default:
				break;
		}

 if( argc != 1)
 {
   fprintf(stderr,"Copyright : J.R. Spanier 1995\n");
   fprintf(stderr,"Version : 1.00\n\n");
   fprintf(stderr,"Usage : pub2html [ -o -c -g ] <reference file>\n");
   fprintf(stderr,"\nPlease Read The Manual Page.\n");
   exit(-1);
 }

 
 for(c=0;c<NUM_ARGS;c++)        /* setup execargv pointers to tabel what */
 {
  what[c] = malloc(MAX_LENGTH*4*sizeof(char));
  execargv[c] = what[c];
 }

 execargv[NUM_ARGS-1] = NULL;
 
 strcpy(inputfilename,*argv);

#ifdef DEBUG
	fprintf(stderr,"Stage 1: Checking Hostname and SUID of program.\n");
#endif

 /* Test for hostname */
 hostname = malloc(20);

 if (geteuid()!=0)
 {
#ifdef DEBUG
	fprintf(stderr,"\n");
#endif

  fprintf(stderr,"Sorry, this program must be SUID root before it will work.\n");
  for(c=0;c<NUM_ARGS;c++)
	free(what[c]);
  free(hostname);
  exit(-1);
 }

 if(gethostname(hostname,20)!=0)
 {
#ifdef DEBUG
	fprintf(stderr,"\n");
#endif

  fprintf(stderr,"Unknown hostname.\n");
  free(hostname);
  for(c=0;c<NUM_ARGS;c++)
	free(what[c]);
  exit(-2);
 }

 if(strcmp(hostname,"capella")!=0)
 {
#ifdef DEBUG
	fprintf(stderr,"\n");
#endif

  fprintf(stderr,"This Software is Licensed To Run On Capella !!\n");
  free(hostname);
  for(c=0;c<NUM_ARGS;c++)
	free(what[c]);
  exit(-2);
 }

 free(hostname);

#ifdef DEBUG
	fprintf(stderr,"Stage 2 : Single User Mode\n");
#endif

 /* Check valid users via SRM_CONF file and protect future access via */
 /* flocking .protect file in PUB2HTML home directory.                */

 /* Test PROTECT file */
 
 sprintf(anotherfilename,"%s%s",PUB2HTML,PROTECT);

 if((fd=open(anotherfilename,O_WRONLY | O_CREAT ,420)) < 0)
 {
#ifdef DEBUG
        fprintf(stderr,"\n"); 
#endif 

  fprintf(stderr,"Cannot Test File Access.\n");
  for(c=0;c<NUM_ARGS;c++)
	free(what[c]);
  exit(-2);
 }

 /* Accessed file, now try to flock it ? */

 if(flock(fd,LOCK_EX | LOCK_NB))
 {
  if(errno==EWOULDBLOCK)
  {
   sprintf(anotherfilename,"%s%s",PUB2HTML,WHO);
   if(!(in=fopen(anotherfilename,"r")))
   {
#ifdef DEBUG
        fprintf(stderr,"\n"); 
#endif 

    fprintf(stderr,"Cannot Find Who is using pub2html.\n");
    close(fd);
    for(c=0;c<NUM_ARGS;c++)
	free(what[c]);
    exit(-2);
   }

   fgets(logname,USER_SIZE,in);

#ifdef DEBUG
        fprintf(stderr,"\n"); 
#endif 

   fprintf(stderr,"User %s is curently running pub2html.\n", logname);
   fclose(in);
   close(fd);
   for(c=0;c<NUM_ARGS;c++)
	free(what[c]);
   exit(-2);
  }
 }

 /* Check for valid users */

 if(parse_srm_file(logname) < 0)
 {
#ifdef DEBUG
        fprintf(stderr,"\n"); 
#endif 

  fprintf(stderr,"Cannot Find Licensed Users\n");
  flock(fd,LOCK_UN);
  close(fd);
  for(c=0;c<NUM_ARGS;c++)
	free(what[c]);
  exit(-3);
 }

 /* Create PROTECT file and lock it */

 sprintf(anotherfilename,"%s%s",PUB2HTML,WHO);
 if(!(in=fopen(anotherfilename,"w")))
 {
#ifdef DEBUG
        fprintf(stderr,"\n"); 
#endif 

  fprintf(stderr,"Cannot Append Current User Into Database.\n");
  flock(fd,LOCK_UN);
  close(fd);
  for(c=0;c<NUM_ARGS;c++)
	free(what[c]);
  exit(-4);
 }

 fprintf(in,"%s",logname);
 fclose(in);

#ifdef DEBUG
	fprintf(stderr,"Stage 3 : Accessing User Reference File");
#endif

 /* Perform ftp access and transfer to publoc directory */
 /* Also fix files using pubquota                       */
 
 /* open input reference in users current directory */

 if(!(in=fopen(inputfilename,"r")))
 {
#ifdef DEBUG
        fprintf(stderr,"\n"); 
#endif 

  fprintf(stderr,"Cannot Read Reference File : %s\n",inputfilename);
  flock(fd,LOCK_UN);
  close(fd);
  for(c=0;c<NUM_ARGS;c++)
	free(what[c]);
  exit(-5);
 }

 /* open global output reference file in its own directory */

 sprintf(outputfilename,"%sreferences",PUB2HTML);
 if(!(out=fopen(outputfilename,"a+")))
 {
#ifdef DEBUG
        fprintf(stderr,"\n"); 
#endif 

  fprintf(stderr,"Cannot Write To Global Reference File.\n");
  fclose(in);
  flock(fd,LOCK_UN);
  close(fd);
  for(c=0;c<NUM_ARGS;c++) 
        free(what[c]);
  exit(-7);
 }

#ifdef DEBUG
	fprintf(stderr," - checking / compressing ps files.\n");
#endif

 fprintf(out,"\n");	/* Make a space in between entries */

 /* Now search and copy */

 /* use anotherfilename as a string buffer */

 while(!(cfg_getline(anotherfilename,MAX_LENGTH,in)))
 {
  if(!strncmp(anotherfilename,"%% ftp: ",8))
  {
   cfg_getword(outputfilename,anotherfilename);		/* Remove %% */
   cfg_getword(outputfilename,anotherfilename);		/* Remove ftp: */
   cfg_getword(outputfilename,anotherfilename);

   /* use hostname and otherpoint as pointers for compressed file check */

   hostname = strchr(outputfilename,'.');
   otherpoint = strrchr(outputfilename,'.');

   strcpy(what[0],COPY);		/* required to get execvp to run an  */
					/* executable. Otherwise fails badly */
   strcpy(what[1],outputfilename); 
   sprintf(what[2],"%s%s",publoc,outputfilename); 
   
   execargv[3] = NULL;	/* what[2][0]='\0'; */

   switch(pid=fork())
   {
    case -1:
	    perror("fork failed");
	    fclose(in);
	    fclose(out);
	    flock(fd,LOCK_UN);
	    close(fd);
  	    for(c=0;c<NUM_ARGS;c++) 
        	free(what[c]);

	    exit(-8);

    case 0:			/* We are a child process */
	   for(c=0;c<NSIG;c++)
		(void)signal(c,SIG_DFL);
	 				/* deactivate all signals child */
					/* inherited  from parent */
					/* The child die here !! */

	   execvp(COPY,execargv);
	   exit(1);

    default:			/* we are the parent if we come here */
	    if(waitpid(pid,NULL,0) == -1)
	    {
		perror("child failed");
		fclose(in);
		fclose(out);
		flock(fd,LOCK_UN);
		close(fd);
  		for(c=0;c<NUM_ARGS;c++) 
        		free(what[c]);

		exit(-8);
	    }
	    break;
   }

   execargv[3] = what[3];	/* restore pointer */
   strcpy(what[1],what[2]);

   /* hostname, otherpoint has been calculated, now confirm check */

   if( hostname != otherpoint)
	if(!strcmp(otherpoint,".gz") || !strcmp(otherpoint,".Z"))
        {
	 fprintf(out,"%%%% ftp: %s\n",outputfilename);
	 pub_quota(&(what[1]),0644);
 	 continue; /* exit the if statement for %% ftp :  ? */
        }

   /* compress or gzip postscript file as determined by select flag */

   /* prepare compression on PUB2HTML/outputfilename */

   execargv[2] = NULL;	/* what[2] = NULL */

   /* Test for required compression */

   if(select = 'Z')
   {
    switch(pid=fork())
    {
     case -1:
            perror("fork failed");
            fclose(in);
            fclose(out);
            flock(fd,LOCK_UN);
            close(fd);
  	    for(c=0;c<NUM_ARGS;c++) 
        	free(what[c]);

            exit(-8);

     case 0:                     /* We are a child process */
           for(c=0;c<NSIG;c++)
                (void)signal(c,SIG_DFL);
                                        /* deactivate all signals child */
                                        /* inherited  from parent */
					/* The child dies here !! */

	   strcpy(what[0],COMPRESS);
           execvp(COMPRESS,execargv);
           exit(1);

     default:                    /* we are the parent if we come here */
            if(waitpid(pid,NULL,0) == -1)
            {
                perror("child failed");
                fclose(in);
                fclose(out);
                flock(fd,LOCK_UN);
                close(fd);
  		for(c=0;c<NUM_ARGS;c++) 
        		free(what[c]);

                exit(-8);
            }
            break;
    }

	fprintf(out,"%%%% ftp: %s.Z\n",outputfilename);
	sprintf(what[0],"%s%s.Z",publoc,outputfilename);
	pub_quota(what,0644);
   }
   else
   {
    switch(pid=fork())
    {
     case -1:
            perror("fork failed");
            fclose(in);
            fclose(out);
            flock(fd,LOCK_UN);
            close(fd);
  	    for(c=0;c<NUM_ARGS;c++) 
        	free(what[c]);

            exit(-8);

     case 0:                     /* We are a child process */
           for(c=0;c<NSIG;c++)
                (void)signal(c,SIG_DFL);
                                        /* deactivate all signals child */
                                        /* inherited  from parent */
					/* The child dies here !! */

	   strcpy(what[0],GZIP);
           execvp(GZIP,execargv);
           exit(1);

     default:                    /* we are the parent if we come here */
            if(waitpid(pid,NULL,0) == -1)
            {
                perror("child failed");
                fclose(in);
                fclose(out);
                flock(fd,LOCK_UN);
                close(fd);
  		for(c=0;c<NUM_ARGS;c++) 
        		free(what[c]);

                exit(-8);
            }
            break;
    }

	fprintf(out,"%%%% ftp: %s.gz\n",outputfilename);
	sprintf(what[0],"%s%s.gz",publoc,outputfilename);
	pub_quota(what,0644);
   }
  }
  else
  {
   fprintf(out,"%s\n",anotherfilename);
  }
 }

 fclose(in);
 fclose(out); 

 execargv[2] = what[2];		/* restore pointer */

#ifdef DEBUG
	fprintf(stderr,"\nStage 4 : HTML generation pass.");
#endif

 /* perform HTML operations */

 sprintf(path,"%sbib",PUB2HTML);

 execargv[5] = NULL;           /* what[5] = NULL; */

 /* test reflabel and if not -l then skip */

 if(!strcmp(reflabel,"-l"))
 {

 /* implements 'bib -l PUB2HTML/references > PUB2HTML/references8ref' */

  strcpy(what[0],"-e");        /* required for calling script within execvp */
  strcpy(what[1],reflabel);

  strcpy(what[2],"-redirect");
  strcpy(what[3],"references8ref");             /* used to write to file */
                                                /* REDIRECTION for perl */
 
  sprintf(what[4],"%sreferences",PUB2HTML);
 
  switch(pid=fork())
  {
   case -1:
            perror("fork failed");
            flock(fd,LOCK_UN);
            close(fd);
  	    for(c=0;c<NUM_ARGS;c++) 
        	free(what[c]);

            exit(-8);

   case 0:                     /* We are a child process */
           for(c=0;c<NSIG;c++)
                (void)signal(c,SIG_DFL);
                                        /* deactivate all signals child */
                                        /* inherited  from parent */
					/* The child dies here */

	   chdir(PUB2HTML);
           execvp(path,execargv);
           exit(1);

   default:                    /* we are the parent if we come here */
            if(waitpid(pid,NULL,0) == -1)
            {
                perror("child failed");
                flock(fd,LOCK_UN);
                close(fd);
  		for(c=0;c<NUM_ARGS;c++) 
        		free(what[c]);

                exit(-8);
            }

            break;
  }

  /* implements 'mv PUB2HTML/references8ref PUB2HTML/references' via system */

  sprintf(what[0],"%s -f %s%s %s",MOVE,PUB2HTML,what[3],what[4]);
  system(what[0]);
 }

 /* implement 'bib -ha PUB2HTML/references > publoc/Publications.html' */

  strcpy(what[0],"-e");	/* Required for running perl scripts in geteuid() */

  strcpy(what[1],"-ha");
  strcpy(what[2],"-redirect");
  strcpy(what[3],"Publications");                 /* used to write to file */
                                                  /* REDIRECTION for perl  */

  sprintf(what[4],"%sreferences",PUB2HTML);

  switch(pid=fork())
  {
   case -1:
            perror("fork failed");
            flock(fd,LOCK_UN);
            close(fd);
  	    for(c=0;c<NUM_ARGS;c++) 
        	free(what[c]);

            exit(-8);

   case 0:                     /* We are a child process */
           for(c=0;c<NSIG;c++)
                (void)signal(c,SIG_DFL);
                                        /* deactivate all signals child */
                                        /* inherited  from parent */
					/* The child dies here !! */

           chdir(publoc);
           execvp(path,execargv);

           exit(1);

   default:                    /* we are the parent if we come here */
            if(waitpid(pid,NULL,0) == -1)
            {
                perror("child failed");
                flock(fd,LOCK_UN);
                close(fd);
  		for(c=0;c<NUM_ARGS;c++) 
        		free(what[c]);

                exit(-8);
            }

            break;
  }

 /* use system command to 'mv /publoc/Publications /publoc/Publications.html' */

 sprintf(what[0],"%s -f %s%s %s%s.html",MOVE,publoc,what[3],publoc,what[3]);
 system(what[0]);
  
#ifdef DEBUG
	fprintf(stderr,"Stage 5 : Allocating files to shared sddress space\n"); 
#endif

 /* do pubquota */

 sprintf(what[0],"%sreferences",PUB2HTML);
 pub_quota(what,0644);
 sprintf(what[0],"%sAbstracts.html",publoc);
 pub_quota(what,0644);
 sprintf(what[0],"%sPublications.html",publoc);
 pub_quota(what,0644);

 /* Now to unlock file */
 /* No need to erase WHO file */

#ifdef DEBUG
	fprintf(stderr,"Stage 6 : Finishing .... \n");
#endif

 flock(fd,LOCK_UN);
 close(fd);
 for(c=0;c<NUM_ARGS;c++)
	free(what[c]);
}

/*----------------------------------------------------------------------------*/

/* parse_srm_file is inspired by NCSA httpd server code */

int parse_srm_file(namelog)
char *namelog;
{
 FILE *srmp;

 char buffer[MAX_HTML_SCRIPT_LENGTH];
 char *username[VALID_USERS];
 char *actualname;

 char w2[MAX_HTML_SCRIPT_LENGTH];
 char w1[MAX_HTML_SCRIPT_LENGTH];
 char *point1, *point2;

 int index = 0 , count;

 actualname = getenv(LOGNAME);	/* This gets the environment name */

 if(actualname[0]=='\0')
  		return(-1);


 /* build usernames file store */

 for(count=0;count<VALID_USERS;count++)
		username[count] = malloc(sizeof(char)*12);

 if(!(srmp=fopen(SRM_CONF,"r")))
 {
  for(count=0;count<VALID_USERS;count++) 
                free(username[count]); 
  return(-1);
 }

 count = 0;

 while(!(cfg_getline(buffer,MAX_HTML_SCRIPT_LENGTH,srmp))) {
    if((buffer[0] != '#' ) && ( buffer[0] != '\0' )) {
	cfg_getword(w1,buffer);

	/* Valid srm keyword */
	if(!strncmp(w1,"Alias",5)) {
		count++;

		cfg_getword(w1,buffer);
		cfg_getword(w2,buffer);

		if(!strcmp(w1,"/publications/"))
		{
		 strcpy(publoc,w2);
		 continue;
		}
		else if(!strcmp(w1,"/icons/"))
			continue;
		else if(!strcmp(w1,"/pics/"))
			continue;

		point1 = strchr(w2,'d');
		point2 = strchr(point1,'/');
		point2[0] = '\0';
		strcpy(username[index++],point1);

		if(count > VALID_USERS + 3)
		{
		 fprintf(stderr,"HTTPD Server Error : To Many Aliases !!\n");
		 fclose(srmp);
		 return(-1);
		}
	}
     }
 }

 fclose(srmp);

 count = -1;

 for(index=0;index<VALID_USERS;index++)
	if(!strcmp(username[index],actualname))
		count=index;
 
 if(count == -1 )
 {
  for(count=0;count<VALID_USERS;count++) 
                free(username[count]); 

  return(-1);
 }

 strcpy(namelog,username[count]);
 for(count=0;count<VALID_USERS;count++) 
                free(username[count]); 

 return(0);
}
 
/*----------------------------------------------------------------------------*/ 
/* cfg_getword inspired/copied from NCSA httpd server code */

cfg_getword(word, line)
char *word;
char *line;
{
 int x=0,y;

 for(x=0;line[x] && isspace(line[x]);x++);
 y=0;
 while(1) {
	if(!(word[y] = line[x]))
		break;
	if(isspace(line[x]))
		if((!x) || (line[x-1] != '\\'))
			break;
	if(line[x] != '\\') ++y;
	++x;
 }

 word[y] = '\0';
 while(line[x] && isspace(line[x])) ++x;
 for(y=0;line[y] = line[x];++x,++y);
}

/*----------------------------------------------------------------------------*/ 
/* cfg_getline inspired/copied from NCSA httpd server code */

int cfg_getline(s, n, f)
char *s;
int n;
FILE *f;
{
    register int i=0;
    register char c;

    s[0] = '\0';
    /* skip leading whitespace */
    while(1) {
        c=(char)fgetc(f);
        if((c != '\t') && (c != ' '))
            break;
    }
    while(1) {
        if((c == '\t') || (c == ' ')) {
            s[i++] = ' ';
            while((c == '\t') || (c == ' ')) 
                c=(char)fgetc(f);
        }
        if(c == CR) {
            c = fgetc(f);
        }
        if((c == 0x4) || (c == LF) || (i == (n-1))) {
            /* blast trailing whitespace */
            while(i && (s[i-1] == ' ')) --i;
            s[i] = '\0';
            return (feof(f) ? 1 : 0);
        }
        s[i] = c;
        ++i;
        c = (char)fgetc(f);
    }
}

/*----------------------------------------------------------------------------*/ 
/* pub_quota was originally coded via previous system administrator and  */
/* PhD student - Matt Jubb. */

int pub_quota(arg, perms)
char *arg[];
mode_t perms;
{
 float quotamb,usagemb;
 char *hostname;
 char quotadev[20];
 int i;

 struct dqblk *quotastruct;
 struct stat *statstruct;

 quotastruct = (struct dqblk *) malloc(sizeof(struct dqblk));
 statstruct = (struct stat *) malloc(sizeof(struct stat));
 hostname = malloc(20); /* 20 characters for the hostname */

 if (gethostname(hostname,20)!=0) strcpy(hostname,"unknown");

 if (strcmp(hostname,IS_CAPELLA)==0) strcpy(quotadev,QUOTACAPELLA);
 else
  strcpy(quotadev,QUOTATALLIS);

 if (quotactl(Q_GETQUOTA,quotadev,SHARED_ID,quotastruct)==-1)
  {
      fprintf(stderr,
         "Host '%s' does not have a quota for 'general use' files.\n",hostname);
      return(-1);
  }

 quotamb = (float) quotastruct->dqb_bsoftlimit/2000;
 usagemb = (float) quotastruct->dqb_curblocks/2000;

 if (usagemb>quotamb)
 {
  fprintf(stderr,"Shared Disk Space Exceeded\n");
  return(-2);
 }

 if (stat(arg[0],statstruct)!=0)
 {
  fprintf(stderr,"File %s \t",
                    strrchr(arg[0],'/') == NULL ? arg[0] : strrchr(arg[0],'/'));
  perror("stat");
  return(-3);
 }
      
 if ((statstruct->st_uid)!=getuid())
 {
  fprintf(stderr,"File %s: \tnot owned by you\n",
                    strrchr(arg[0],'/') == NULL ? arg[0] : strrchr(arg[0],'/'));
 }
      
 if (chown(arg[0],SHARED_ID,SHARED_GROUP)!=0)
 {
  fprintf(stderr,"File %s \t",
                    strrchr(arg[0],'/') == NULL ? arg[0] : strrchr(arg[0],'/'));
  perror("chown");
  return(-4);
 }

 if (chmod(arg[0],perms)!=0)
 {
  fprintf(stderr,"File %s \t",
                    strrchr(arg[0],'/') == NULL ? arg[0] : strrchr(arg[0],'/'));

  perror("chmod");
  return(-5);
 }

 if (quotactl(Q_GETQUOTA,quotadev,SHARED_ID,quotastruct)==-1)
 {
  perror("quotactl");
  return(-6);
 }

 fprintf(stderr,"File %s: \tOK\n",
		    strrchr(arg[0],'/') == NULL ? arg[0] : strrchr(arg[0],'/'));

 if ((quotastruct->dqb_curblocks)>(quotastruct->dqb_bsoftlimit))
 {
  fprintf(stderr,"Successfully processed file.\n");
  fprintf(stderr,"'SHARED' OWNERSHIP QUOTA NOW EXCEEDED!\n");
  return(-2);
 }
     
}  
