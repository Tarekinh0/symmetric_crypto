#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

//authors : Tarek MAHFOUDH et Grigorios PAPADAS

int test(char* nom);    //test file exists
long count(char nom[]); //counts bytes in file
void copieDansTab(char nom[], char temp[]); //copie le fichier dans un tab temp;
void copieDansFich(char nom[], char temp[]);    //copie le tab temp dans le fichier
void copyFileToFile(char nom_original[], char nom_copie[]); //copier un fichier dans un autre fichier
void charToBin(int *tab, char nombre);   //transpose un entier en base decimal dans un tableau sous la forme binaire
void binToChar(int *tab, char *nombre);  //transpose un tableau en base binaire dans un entier en base decimal

void Decallage(int* decal ,unsigned char* tab_gauche, unsigned char* tab_droit, int i); //helps generate keys
int prochain(int i);    //helps generate keys and used in Decallage
void KeyGen(int N, const char password[], unsigned char ***keys[]); //generates keys
char cypherChar(char c, int i);   //not used anymore, helps cypher chars

//Add bytes to have blocks of 4 bytes
void Add(char nom[]);    //padding procedure: rounds up number of bytes to 4

//Encryption

void encryption(char nomC[], unsigned char *keys[], int N); //structure du chiffrement (contient 1,2,3,4,5)
void step1_encryption(char nom[], unsigned char key[]);     //ancienne version du chiffrement 1
void step1_encryption_amelioree(char nom[],unsigned char key[]);    //etape 1 chiffrement
void step2_encryption(char nom[]);  //etape 2 chiffrement
void step3_encryption(char nom[]);  //etape 3 chiffrement
void step4_encryption(char nom[],  unsigned char key[]);    //etape 4 chiffrement
void step5_encryption(char nom[]);  //etape 5 chiffrement


//Decryption

void decryption(char nomD[], unsigned char *keys[], int N); //structure du dechiffrement (contient 1,2,3,4,5)
void step5_decryption(char nom[]);  //etape 5 dechiffrement
void step4_decryption(char nom[],  unsigned char key[]);    //etape 4 dechiffrement
void step3_decryption(char nom[]);  //etape 3 dechiffrement
void step2_decryption(char nom[]);  //etape 2 dechiffrement
void step1_decryption_amelioree(char nom[],unsigned char key[]);    //ancienne version du dechiffrement 1
void step1_decryption(char nom[],unsigned char key[]);  //etape 1 dechiffrement

//take off added bytes to gain back the integrity of the file
void Remove(char nom[]);  //detects the number x of added 000000000 and removes them (x going from 0 to 2)

///@brief C'est la fonction main : elle regroupe tout le programme qui va permettre à l'utilisateur de crypter et/ou décrypter à sa guise et en rentrant les paramètres qui sont nécessaires.
///La fonction main regroupe et fait appel à l'ensemble des fonctions et procédures. C'est ici que l'utilisateur rentrera toutes les données.
int main() {

    printf("\nVoulez-vous crypter ou decrypter un fichier ? Entrer 1 2 ou 3.\n"
           "1 pour crypter\n"
           "2 pour decrypter\n"
           "3 pour lancer une demo (crypter et decrypter)"
           "\n");   //on demande a l'utilisateur le mode qu'il veut
    int choix = 0;
    scanf("%d", &choix);    //on recupere le choix
    if( (choix != 1) && (choix != 2) && (choix != 3) ) return -1;   //on test si son choix est valide

    printf("Entrer le nom du fichier (avec extension) : \n");   //on demande le nom du fichier
    char nom[255];
    scanf("%s", nom);   //on recupere le nom de fichier
    if (test(nom) == -1) return -1; //on test pour voir si le fichier existe, sinon on arrete le programme

    int N;
    printf("Entrer le nombre d'iterations : \n");
    //on demande le nombre de couches de chiffrement ou dechiffrement a appliquer
    scanf("%d", &N);    //on recupere le nombre d'iterations

    char password[9];
    printf("Entrez un mot de passe d'obligatoirement 8 caracteres: \n");    //on demande un mdp de 8 caracters
    scanf("%s", password);  //on le recupere
    if (strlen(password) != 8){
        printf("erreur : entrer 8 caracteres");
        return(-1);     //on arrete le programme si la longueur du mdp != 8
    }

    unsigned char **keys;
    keys = calloc(N+1, sizeof(char*));  //on initialise les N pointeurs pour sous-cles
    for(int i = 0; i <= N ; i++){
        keys[i] = calloc(strlen(password), sizeof(char));   //on donne une longueur de 8 aux sous-cles
    }

    KeyGen(N, password, keys);  //on genere les sous-cles
    //keys[0] est le mot de passe rentre par l'utilisateur
    //a partir de keys[1] a key[31](max) on a 31 sous-cles differentes l'une de l'autre et differentes du mot
    //de passe.

//
//    for(int i = 1; i <= N ; i++){
//        for(int j = 0; j < 8; j++){
//            printf("%c", keys[i][j]);         //permet de lire les differentes sous-cles generees
//        }
//        printf("\n");
//    }

/* a partir de ligne 99 a 114 on cree les noms de fichiers
 * donc pour par exemple : "xxxx".ext on aura
 * nomC = "xxxx"_C.cry
 * nomD = "xxxx"_D.ext */
    char nomC[255];
    char nomD[255];
    strcpy(nomC, nom);      //on commence par copier dans nomC
    strcpy(nomD, nom);      //et nomD
    int j = 0;
    char ext[10];   //chaine de caractere pour mettre l'extension du fichier d'origine
    while(nomC[j] != '.')   //on trouve la position du point
        j++;
    for (int k = 0 ; k < 5 ; k++){
        ext[k] = nom[j+k];  //on copie l'extension du fichier
    }
    nomC[j] = '\0'; //on coupe nomC a partir du point pour avoir nomC : "xxxx.ext" -> "xxxx"
    strcat(nomC, "_C.cry"); //on concatene les 2 chaines de caracteres : "xxxx" -> "xxxx_C.cry"
    nomD[j] = '\0'; //on coupe nomD a partir du point pour avoir nomD : "xxxx.ext" -> "xxxx"
    strcat(nomD, "_D"); //on concatene les 2 chaines de caracteres : "xxxx" -> "xxxx_D"
    strcat(nomD, ext);  //et puis : "xxxx_D" -> "xxxx_D.ext"

    switch(choix){
        case 1 :
            copyFileToFile(nom, nomC);  //on copie le contenu du fichier d'origine dans un autre fichier
            //on va chiffrer l'autre fichier qui est une copie du premier, pour quand meme garder l'original
            Add(nomC);            //on fait le padding pour le fichier
            encryption(nomC, keys, N);  //on chiffre le fichier
            break;

        case 2 :
            copyFileToFile(nom, nomD);  //on copie le contenu du fichier chiffre dans un autre fichier
            //on va dechiffrer l'autre fichier qui est une copie du chiffre, pour quand meme garder la verion chifree
            decryption(nomD, keys, N);  //on dechiffre le fichier
            Remove(nomD);   //on enleve le padding pour le fichier
            break;

        case 3 :
            //dans le cas 3 : on refait exacetement le 1 et le 2 a la suite. voir en haut pour les commentaires
            copyFileToFile(nom, nomC);
            Add(nomC);
            encryption(nomC, keys, N);
            copyFileToFile(nomC, nomD);
            decryption(nomD, keys, N);
            Remove(nomD);
            break;
        default:
            //si il y a erreur, on sort du programme en affichant le message d'erreur
            printf("\nError");
            return -1;
            break;
    }
    for(int i = 0; i <= N ; i++){
        free(keys[i]);   //libere les pointeurs
    }
    free(keys); //on libere le pointeur sur pointeurs


    printf("Thank you for using this program !\nPress ENTER to exit.");
    getchar();
    getchar();  //appuyez sur entrer pour sortir et terminer le programme
    return 0;
}




/// @brief Cette procédure est une structure de chiffrement qui utilise les 5 fonctions de chiffrement
/// @brief Elle réalise les N chiffrements nécessaires pour crypter le message.
/// @param[in] N : Nombre d'itérations
/// @param[in] nomD[] : Le tableau contenant le fichier à chiffrer sous forme de caractères
/// @param[in] *keys[] : Le tableau contenant les sous-clés
/// @param[out] nomD[] : Le fichier chiffré
/// @see step1_encryption_amelioree(), step2_encryption(), step3_encryption(), step4_encryption(), step5_encryption()
void encryption(char nomC[], unsigned char *keys[], int N){
    //On met la boucle for qui fera les N iterations de 1 a 5
    for(int i = 1; i <= N ;i++){
//        step1_encryption(nomC, keys[i]);          //obsolete
        step1_encryption_amelioree(nomC, keys[i]);
        step2_encryption(nomC);
        step3_encryption(nomC);
        step4_encryption(nomC, keys[i]);
        step5_encryption(nomC);
    }
}

/// @brief Cette procédure est une structure de déchiffrement qui utilise les 5 fonctions de déchiffrement.
/// @brief Elle réalise les N déchiffrements nécessaires pour décrypter le message.
/// @param[in] N : Nombre d'itérations
/// @param[in] nomD[] : Le tableau contenant le fichier à déchiffrer sous forme de caractères
/// @param[in] *keys[] : Le tableau contenant les sous-clés
/// @param[out] nomD[] : Le fichier déchiffré
/// @see step1_decryption_amelioree(), step2_decryption(), step3_decryption(), step4_decryption(), step5_decryption()
void decryption(char nomD[], unsigned char *keys[], int N){
    //On met la boucle for qui fera les N iterations de 5 a 1 pour defaire les chiffrements successifs
    for(int i = N; i >= 1 ;i--) {
        step5_decryption(nomD);
        step4_decryption(nomD, keys[i]);
        step3_decryption(nomD);
        step2_decryption(nomD);
        step1_decryption_amelioree(nomD, keys[i]);
//        step1_decryption(nomD, keys[i]);      //obsolete
    }
}
/// @brief Procédure de chiffrement 1
///
///
/// Cette procédure utilise les 8 caractères de la clé Ki afin de créer un poids de la façon suivante :\n
/// poids = -key[0]+key[1]-key[3]+key[4]-key[5]+key[6]-key[7] (addition/soustraction alternée).\n
/// Par la suite ce poids est ajouté à tous les caractères du tableau **nom[]**.\n
/// On applique alors un Code César de decalage **poids** à l'ensemble du fichier.\n
/// @param[in] nom[] : Tableau contenant le fichier à chiffrer sous forme de caractères
/// @param[in] key[] : Tableau contenant la sous-clé K d'indice i
/// @param[out] nom[] : Tableau contenant le fichier chiffré
/// @warning Cette procédure est première version non utilisée qui n'est plus utilisée, voir  step1_encryption_amelioree()
/// @see count(), copieDansTab(), copieDansFich()
void step1_encryption(char nom[], unsigned char key[]){
    long length = count(nom);   //on recupere le nombre d'octet et donc de caracteres
    char *temp = calloc(length, sizeof(char));  //on prepare le tableau dans lequel on va deverser le fichier
    copieDansTab(nom, temp);    //on copie le fichier dans le tableau
    int poids_mdp = -key[0]+key[1]-key[3]+key[4]-key[5]+key[6]-key[7];     //on definit le poids
    for(int k = 0; k < length; k+=4){
        temp[k] += (char)poids_mdp; //le modulo se fais seul    //on fais le decalage
    }
    copieDansFich(nom, temp);   //on remet le teableau modifie dans le fichier
    free(temp); //on libere le pointeur sur tableau
}

/// @brief Procédure de déchiffrement 1
///
/// Cette procédure utilise les 8 caractères de la clé Ki afin de créer un poids de la façon suivante :\n
/// poids = -key[0]+key[1]-key[3]+key[4]-key[5]+key[6]-key[7] (addition/soustraction alternée).\n
/// Par la suite on soustrais le poids à tous les caractères du tableau **nom[]** afin de les déchiffrer.\n
/// On inverse alors le Code César de decalage **poids** à l'ensemble du fichier.\n
/// @param[in] nom[] : Tableau contenant le fichier à déchiffrer sous forme de caractères
/// @param[in] key[] : Tableau contenant la sous-clé K d'indice i
/// @param[out] nom[] : Tableau contenant le fichier déchiffré
/// @warning Cette procédure est première version non utilisée qui n'est plus utilisée, voir step1_decryption_amelioree()
/// @see count(), copieDansTab(), copieDansFich()
void step1_decryption(char nom[],unsigned char key[]){
    long length = count(nom);   //on recupere le nombre d'octet et donc de caracteres
    char *temp = calloc(length, sizeof(char));  //on prepare le tableau dans lequel on va deverser le fichier
    copieDansTab(nom, temp);    //on copie le tableau
    int poids_mdp = -key[0]+key[1]-key[3]+key[4]-key[5]+key[6]-key[7];  //on retrouve le poids definit
    for(int k = 0; k < length; k+=4){
        temp[k] -= (char)poids_mdp; //on enleve le decalage
    }
    copieDansFich(nom, temp);   //on remet le tableau modifie dans le fichier
    free(temp); //on libere le pointeur sur tableau
}


/// @brief Procédure de chiffrement 1
///
///
/// Cette procédure utilise un Key Scheduling Algorithm pour créer une table de permutation.\n
/// La table possède 256 entrées différentes.\n
/// Suivant la table on change les caractères de **nom[]**.\n
/// @param[in] nom[] : Tableau contenant le fichier à chiffrer sous forme de caractères
/// @param[in] key[] : Tableau contenant la sous-clé K d'indice i
/// @param[out] nom[] : Tableau contenant le fichier chiffré
/// @note * La table de permutation est différente pour chaque itération (elle dépends de la sous clé).
/// @note * La fonction peut traiter tous les caractères de la table ASCII (avec ASCII étendue)
/// @see count(), copieDansTab(), copieDansFich()
void step1_encryption_amelioree(char nom[],unsigned char key[]){
    long length = count(nom);   //on recupere le nombre d'octet et donc de caracteres
    char *temp = calloc(length, sizeof(char));  //on prepare le tableau dans lequel on va deverser le fichier
    copieDansTab(nom, temp);    //on copie le fichier dans un tableau
    int Karray[256];
    int Sarray[256];
    for(int i=0;i<256;i++){

        int nombre=(int)key[i%8]; //Conversion du caractere key[i%8]  en un entier
        if(nombre<0)nombre=nombre+256; //si le nombre est >127 il devient negatif donc on le ramene a un positif
        Karray[i]= nombre%256; //On l'affecte au tableau Karray

        Sarray[i]=i;//Initialisation du tableau Sarray
    }

    int j=0;
    for(int i=0;i<256;i++){
        j=(j+Sarray[i]+Karray[i])%256; // initialisation de j
        int transfer=Sarray[i];//permutation entre s[i] et s[j]
        Sarray[i]=Sarray[j];
        Sarray[j]=transfer;
    }


    for(int i=0;i<length;i++){
        int nombre=(int)temp[i];//Conversion du caractere en un entier
        if(nombre<0)nombre=nombre+256; //si le nombre est negatif on le ramene a un nombre positif
        nombre=nombre%256;
        temp[i]=(char)Sarray[nombre]; // affectation de la nouvelle valeur suivant la table de permutation Sarray
    }
    copieDansFich(nom, temp);   //on met le tableau modifie dans le tableau
}

/// @brief Procédure de déchiffrement 1
///
///
///  Cette procédure utilise un Key Scheduling Algorithm pour créer une table de permutation (même table que step1_encryption_amelioree).\n
///  La table possède 256 entrées différentes.\n
///  Pour chaque caractère de **nom[]** on trouve son antécédent suivant la table afin de le déchiffrer.\n
/// @param[in] nom[] : Tableau contenant le fichier à déchiffrer sous forme de caractères
/// @param[in] key[] : Tableau contenant la sous-clé K d'indice i
/// @param[out] nom[] : Tableau contenant le fichier déchiffré
/// @note * La table de permutation est différente pour chaque itération (elle dépends de la sous clé).
/// @note * La procédure peut traiter tous les caractères de la table ASCII (avec ASCII étendue)
/// @see count(), copieDansTab(), copieDansFich()
void step1_decryption_amelioree(char nom[],unsigned char key[]){
    long length = count(nom);   //on recupere le nombre d'octet et donc de caracteres
    char *temp = calloc(length, sizeof(char));  //on prepare le tableau dans lequel on va deverser le fichier
    copieDansTab(nom, temp);    //on copie le tableau
    int Karray[256];
    int Sarray[256];
    for(int i=0;i<256;i++){

        int nombre=(int)key[i%8]; //Conversion du caractere key[i%8]  en un entier
        if(nombre<0)nombre=nombre+256; //si le nombre est >127 il devient negatif donc on le ramene a un positif
        Karray[i]= nombre%256; //On l'affecte au tableau Karray

        Sarray[i]=i;//Initialisation du tableau Sarray
    }

    int j=0;
    for(int i=0;i<256;i++){
        j=(j+Sarray[i]+Karray[i])%256; // initialisation de j
        int transfer=Sarray[i];//permutation entre s[i] et s[j]
        Sarray[i]=Sarray[j];
        Sarray[j]=transfer;
    }


    for(int i=0;i<length;i++){
        int nombre=(int)temp[i]; //Conversion du caractere en un entier
        if(nombre<0)nombre=nombre+256; //si le nombre est negatif on le ramene a un nombre positif
        int k;
        for(k=0;k<256;k++)if(Sarray[k]== nombre)break; //On recherche la valeur correspondante a la variable nombre dans le tableau de permutation
        temp[i]=(char)k; // affectation de valeur avant chiffrement suivant la table de permutation Sarray
    }
    copieDansFich(nom, temp);   //on met le tableau modifie dans le tableau
}

/* Crypter etape 2:
 * 1->2
 * 2->4
 * 3->1
 * 4->3
 */

/// @brief Procédure de chiffrement 2
///
///
/// Cette fonction traite le fichier par blocs de 4 octets et les permute de façon suivante :
/// * 1->2
/// * 2->4
/// * 3->1
/// * 4->3
/// @param[in] nom[] : Le tableau contenant le fichier à chiffrer sous forme de caractères
/// @param[out] nom[] : Le fichier chiffré
/// @see count(), copieDansTab(), copieDansFich()
void step2_encryption(char nom[]){
    long length = count(nom);   //on recupere le nombre d'octet et donc de caracteres
    char *fichier = calloc(length, sizeof(char));   //on prepare le tableau dans lequel on va deverser le fichier
    copieDansTab(nom, fichier); //on copie le tableau
    char temp[4];   //on intitaialise un tableau temporaire pour les permutations
    for(int i = 0; i < length ; i+=4){
        //on recree notre permutation qu'on trouve ci-dessus
        temp[0] = fichier[i+1];
        temp[1] = fichier[i+3];
        temp[2] = fichier[i];
        temp[3] = fichier[i+2];
        //on remet nos permutations dans le tableau
        fichier[i] = temp[0];
        fichier[i+1] = temp[1];
        fichier[i+2] = temp[2];
        fichier[i+3] = temp[3];
    }
    copieDansFich(nom, fichier);    //on met le tableau modifie dans le tableau
    free(fichier); //on libere le pointeur sur tableau

}

/* Decrypter etape 2:
 * 1->3
 * 2->1
 * 3->4
 * 4->2
 */

/// @brief Procédure de déchiffrement 2
///
///
/// Cette procédure traite le fichier par blocs de 4 octets et les permute de façon suivante :
/// * 1->3
/// * 2->1
/// * 3->4
/// * 4->2
/// @param[in] nom[] : Le tableau contenant le fichier à déchiffrer sous forme de caractères
/// @param[out] nom[] : Le fichier déchiffré
/// @see count(), copieDansTab(), copieDansFich()
void step2_decryption(char nom[]){
    long length = count(nom);   //on recupere le nombre d'octet et donc de caracteres
    char *fichier = calloc(length, sizeof(char));   //on prepare le tableau dans lequel on va deverser le fichier
    copieDansTab(nom, fichier); //on copie le tableau
    char temp[4];   //on intitaialise un tableau temporaire pour les permutations
    for(int i = 0; i < length ; i+=4){
        //on recree notre permutation qu'on trouve ci-dessus
        temp[0] = fichier[i+2];
        temp[1] = fichier[i];
        temp[2] = fichier[i+3];
        temp[3] = fichier[i+1];
        //on remet nos permutations dans le tableau
        fichier[i] = temp[0];
        fichier[i+1] = temp[1];
        fichier[i+2] = temp[2];
        fichier[i+3] = temp[3];
    }
    copieDansFich(nom, fichier);    //on met le tableau modifie dans le tableau
    free(fichier); //on libere le pointeur sur tableau

}


/// @brief Procédure de chiffrement 3
///
///
///Cette fonction consiste en un transformation matricielle est de la forme <b>Hx+C</b>, avec :\n
///\verbatim
///H = {1,0,0,0,1,1,1,1}        C = {1}
///    {1,1,0,0,0,1,1,1}            {1}
///    {1,1,1,0,0,0,1,1}            {0}
///    {1,1,1,1,0,0,0,1}            {0}
///    {1,1,1,1,1,0,0,0}            {0}
///    {0,1,1,1,1,1,0,0}            {1}
///    {0,0,1,1,1,1,1,0}            {1}
///    {0,0,0,1,1,1,1,1}            {0}\endverbatim
/// Le fichier est chiffré octet pas octet
/// @param[in] nom[] : Le tableau contenant le fichier à chiffrer sous forme de caractères
/// @param[out] nom[] : Le fichier chiffré.
/// @see count(), copieDansTab(), copieDansFich(), charToBin(), binToChar()
void step3_encryption(char nom[]){
    //on met nos matrices pour le chiffrement
    int MAT[8][8] = {
            {1,0,0,0,1,1,1,1},
            {1,1,0,0,0,1,1,1},
            {1,1,1,0,0,0,1,1},
            {1,1,1,1,0,0,0,1},
            {1,1,1,1,1,0,0,0},
            {0,1,1,1,1,1,0,0},
            {0,0,1,1,1,1,1,0},
            {0,0,0,1,1,1,1,1},
    };
    int MATC[8] =
            {1,1,0,0,0,1,1,0};

    long length = count(nom);   //on recupere le nombre d'octet et donc de caracteres
    char *tableau = calloc(length, sizeof(char));   //on prepare le tableau dans lequel on va deverser le fichier
    copieDansTab(nom, tableau); //on copie le tableau
    int entree[8];  //on initialise 2 tableaux, l'un pour contenir les bits d'entree et
    int sortie[8];  // l'autre les bits de sortie
    for(int i = 0 ; i < length ; i++){
        charToBin(entree, tableau[i]);   //on transforme le caractere en serie de 8 bits
        for(int j = 0; j < 8 ; j++){
            sortie[j] = 0;
            for(int k = 0 ; k < 8 ; k++){
                sortie[j] += MAT[j][k] * entree[k]; //on fais la multiplication matricielle Hx
            }
            sortie[j] %= 2; //on fais le modulo 2 (on a affaire a des bits)
        }

        for(int j = 0 ; j < 8 ; j++){
            sortie[j] += MATC[j];   //on ajoute le C de : Hx + C
            sortie[j] %= 2; //on fais le modulo 2 (on a affaire a des bits)
        }

        binToChar(sortie, &tableau[i]);  //on retransforme la serie de bits recuperee en un caractere
    }
    copieDansFich(nom, tableau);    //on met le tableau modifie dans le tableau
    free(tableau); //on libere le pointeur sur tableau

}
/// @brief Procédure de déchiffrement 3
///
///
/// Cette procédure consiste en une transformation matricielle inverse de step3_encyption .
///La transformation matricielle est de la forme <b>H'x+C'</b>, avec :\n
///\verbatim
/// H' = {0,0,1,0,0,1,0,1}     C' = {1}
///      {1,0,0,1,0,0,1,0}          {0}
///      {0,1,0,0,1,0,0,1}          {1}
///      {1,0,1,0,0,1,0,0}          {0}
///      {0,1,0,1,0,0,1,0}          {0}
///      {0,0,1,0,1,0,0,1}          {0}
///      {1,0,0,1,0,1,0,0}          {0}
///      {0,1,0,0,1,0,1,0}          {0}
///\endverbatim
/// Le fichier est chiffré octet pas octet.
/// @param[in] nom[] : Le tableau contenant le fichier à déchiffrer sous forme de caractères
/// @param[out] nom[] : Le fichier déchiffré
/// @see count(), copieDansTab(), copieDansFich(), charToBin(), binToChar()
void step3_decryption(char nom[]){
    //on met nos matrices pour le dechiffrement
    int MAT[8][8] = {
            {0,0,1,0,0,1,0,1},
            {1,0,0,1,0,0,1,0},
            {0,1,0,0,1,0,0,1},
            {1,0,1,0,0,1,0,0},
            {0,1,0,1,0,0,1,0},
            {0,0,1,0,1,0,0,1},
            {1,0,0,1,0,1,0,0},
            {0,1,0,0,1,0,1,0},
    };
    int MATC[8] =
            {1,0,1,0,0,0,0,0};

    long length = count(nom);   //on recupere le nombre d'octet et donc de caracteres
    char *tableau = calloc(length, sizeof(char));   //on prepare le tableau dans lequel on va deverser le fichier
    copieDansTab(nom, tableau); //on copie le tableau
    int entree[8];  //on initialise 2 tableaux, l'un pour contenir les bits d'entree et
    int sortie[8];  // l'autre pour les bits de sortie
    for(int i = 0 ; i < length ; i++){
        charToBin(entree, tableau[i]);   //on transforme le caractere en serie de 8 bits
        for(int j = 0; j < 8 ; j++){
            sortie[j] = 0;
            for(int k = 0 ; k < 8 ; k++){
                sortie[j] += MAT[j][k] * entree[k]; //on fais la multiplication matricielle H'y
            }
            sortie[j] %= 2; //on fais le modulo 2 (on a affaire a des bits)
        }
        for(int j = 0 ; j < 8 ; j++){
            sortie[j] += MATC[j];   //on ajoute le C de : H'y + C'
            sortie[j] %= 2; //on fais le modulo 2 (on a affaire a des bits)
        }
        binToChar(sortie, &tableau[i]);  //on retransforme la serie de bits recuperee en un caractere
    }
    copieDansFich(nom, tableau);    //on met le tableau modifie dans le tableau
    free(tableau); //on libere le pointeur sur tableau

}
/// @brief Procédure de chiffrement 4
///
///
/// Dans cette procédure on applique la fonction XOR entre une octet et un caractère de la sous-clé Ki
/// Le fichier est chiffré par blocs de 4 octets de sorte qu’au premier bloc on utilise la première moitié de la sous-clé Ki et au deuxième bloc la deuxième moitié de Ki.
/// @param[in] nom[] : Tableau contenant le fichier à chiffrer sous forme de caractères
/// @param[in] key[] : Tableau contenant la sous-clé K d'indice i
/// @param[out] nom[] : Tableau contenant le fichier chiffré
/// @see count(), copieDansTab(), copieDansFich()
void step4_encryption(char nom[],  unsigned char key[]){
    long length = count(nom);   //on recupere le nombre d'octet et donc de caracteres
    char *fichier = calloc(length, sizeof(char));   //on prepare le tableau dans lequel on va deverser le fichier
    copieDansTab(nom, fichier); //on copie le tableau
    for(int k = 0; k < length; k+=4){   //on travaille par bloc
        //on alterne : chaque bloc par multiple de 2
        //sera chiffre par une moitie du mot de pass
        //c'est une amelioration qu'on a apportee
        for(int i = 0; i < 4; i++){
            //on fais l'operation du XOR grace a l'operateur binaire ^
            fichier[k+i] = fichier[k+i] ^ key[(k+i) % 8];
        }
    }
    copieDansFich(nom, fichier);    //on met le tableau modifie dans le tableau
    free(fichier); //on libere le pointeur sur tableau
}

/// @brief Procédure de déchiffrement 4
///
///
/// La procédure inverse est exactement la même que celle de chiffrement puisqu'il s'agit d'une fonction XOR.
/// @param[in] nom[] : Tableau contenant le fichier à déchiffrer sous forme de caractères
/// @param[in] key[] : Tableau contenant la sous-clé K d'indice i
/// @param[out] nom[] : Tableau contenant le fichier déchiffré
/// @see step4_encryption(), count(), copieDansTab(), copieDansFich()
//La bijective est exactement pareil puisqu'il s'agit d'une operation XOR
void step4_decryption(char nom[],  unsigned char key[]){
    long length = count(nom);   //on recupere le nombre d'octet et donc de caracteres
    char *fichier = calloc(length, sizeof(char));   //on prepare le tableau dans lequel on va deverser le fichier
    copieDansTab(nom, fichier); //on copie le tableau
    for(int k = 0; k < length; k+=4){
        //l'operation XOR est sa meme bijective, aucunement
        //besoin de changer le code
        for(int i = 0; i < 4; i++){
            //on fais l'operation du XOR grace a l'operateur binaire ^
            fichier[k+i] = fichier[k+i] ^ key[(k+i)%8];
        }
    }
    copieDansFich(nom, fichier);    //on met le tableau modifie dans le tableau
    free(fichier); //on libere le pointeur sur tableau
}


/// @brief Procédure de chiffrement 5
///
///
///\verbatim On applique le système linéaire suivant :
///
///     Z[0] = Y[0] + Y[1]
///     z[1] = Y[0] + Y[1] + Y[2]
///     Z[2] = Y[1] + Y[2] + Y[3]
///     Z[3] = Y[2] + Y[3]\endverbatim
/// @param[in] nom[] : Le tableau contenant le fichier à chiffrer sous forme de caractères
/// @param[out] nom[] : Le fichier chiffré
/// @note * Avant de stocker les résultats dans le fichier on applique modulo 256
/// @note * La procédure peut traiter tous les caractères de la table ASCII (avec ASCII étendue)
/// @see count(), copieDansTab(), copieDansFich(), CharToBin(), binToChar()
void step5_encryption(char nom[]){
    int length = count(nom);    //on recupere le nombre d'octet et donc de caracteres
    char *tableau = calloc(length, sizeof(char));   //on prepare le tableau dans lequel on va deverser le fichier
    copieDansTab(nom, tableau); //on copie le tableau
    int temp[4];  //on creer un tableau temporaire pour faire les permutations

    //on travaille par blocs de 4
    for(int i = 0 ; i < length ; i += 4){

        //on ecrit le systeme lineaire
        temp[0]=(int)tableau[i]+(int)tableau[i+1];
        temp[1]=(int)tableau[i]+(int)tableau[i+1]+(int)tableau[i+2];
        temp[2]=(int)tableau[i+1]+(int)tableau[i+2]+(int)tableau[i+3];
        temp[3]=(int)tableau[i+2]+(int)tableau[i+3];

        //on fait les permutations (toujours avec le modulo)
        tableau[i]=(char) (temp[0] % 256);
        tableau[i+1]=(char) (temp[1] % 256);
        tableau[i+2]=(char) (temp[2] % 256);
        tableau[i+3]=(char) (temp[3] % 256);
    }
    copieDansFich(nom, tableau);    //on met le tableau modifie dans le tableau
    free(tableau); //on libere le pointeur sur tableau

}

/// @brief Procédure de déchiffrement 5
///
///
///@verbatim On applique le système linéaire suivant :
///
///     Y[0] = Z[0] - Z[2] + Z[3]
///     Y[1] = Z[2] - Z[3]
///     Y[2] = - Z[0] + Z[1]
///     Y[3] = Z[0] - Z[1] + Z[3]\endverbatim
/// @param[in] nom[] : Le tableau contenant le fichier à déchiffrer sous forme de caractères
/// @param[out] nom[] : Le fichier déchiffré
/// @note * Avant de stocker les résultats dans le fichier on applique modulo 256
/// @note * La procédure peut traiter tous les caractères de la table ASCII (avec ASCII étendue)
/// @see count(), copieDansTab(), copieDansFich(), CharToBin(), binToChar()
void step5_decryption(char nom[]){
    int length = count(nom);    //on recupere le nombre d'octet et donc de caracteres
    char *tableau = calloc(length, sizeof(char));   //on prepare le tableau dans lequel on va deverser le fichier
    copieDansTab(nom, tableau); //on copie le tableau
    int temp[4];    //on creer un tableau temporaire pour faire les permutations

    //on travaille par blocs de 4
    for(int i = 0 ; i < length ; i += 4){

        //on ecrit le systeme lineaire
        temp[0]=(int)tableau[i]-(int)tableau[i+2]+(int)tableau[i+3];
        temp[1]=(int)tableau[i+2]-(int)tableau[i+3];
        temp[2]=-(int)tableau[i]+(int)tableau[i+1];
        temp[3]=(int)tableau[i]-(int)tableau[i+1]+(int)tableau[i+3];

        //on fait les permutations (toujours avec le modulo)
        tableau[i]=(char) (temp[0] % 256);
        tableau[i+1]=(char) (temp[1] % 256);
        tableau[i+2]=(char) (temp[2] % 256);
        tableau[i+3]=(char) (temp[3] % 256);
    }
    copieDansFich(nom, tableau);    //on met le tableau modifie dans le tableau
    free(tableau); //on libere le pointeur sur tableau
}

/// @brief Cette fonction permet de tester l'existance du fichier choisi
/// @param *nom : Pointeur sur le fichier choisi
/// @return  0: Le fichier existe
/// @return -1: Erreur
/// @note une condition dans le main verifie si test rend -1 le main s'arrette et rend -1
int test(char* nom){
    FILE *ptr;
    ptr = fopen(nom, "r");  //on ouvre le fichier en mode Read
    if( ptr == NULL )  {    //on verifie si le fichier existe
        perror ("Error opening file");  //si on 'n'arrive pas a ouvrir le fichier, on affiche un message d'erreur
        return(-1); //une condition dans le main verifie si test rend -1 ; si c'est le cas ; le main rend -1
    }
    fclose(ptr);
    free(ptr);  //on libere le pointeur sur fichier
    return 0;
}

/// @brief Cette fonction permet de compter le nombre d'octets (caractères) dans un fichier
/// @param nom[] : Le nom fichier choisi
/// @return La longueur du fichier en octets
long count(char nom[])
{
    FILE *ptr;
    ptr = fopen(nom , "r"); //on ouvre le fichier en mode Read
    fseek(ptr, 0, SEEK_END);    //on se place a la fin
    long length  = ftell(ptr);  //on lit la longueur
    fclose(ptr);    //on ferme le fichier
    free(ptr);  //on libere le pointeur sur fichier
    return length;  //on retourne la longueur
}


/// @brief Cette procédure permet de copier un fichier dans un tableau
/// @param[in] nom[] :  Nom du fichier choisi
/// @param[out] temp[] : Tableau où on copie le fichier
/// @note **nom[]** sert aussi d’argument à la fonction **count** pour calculer la taille du fichier
/// @see count()
void copieDansTab(char nom[], char temp[]){
    FILE *ptr;
    long length = count(nom);   //on recupere le nombre d'octet et donc de caracteres
    ptr = fopen(nom, "r");  //on ouvre le fichier en mode Read
    for(int i = 0; i < length ; i++)
    {
        //on copie chaque caractere dans un fichier grace a fgetc (on aurait pu faire sans la longueur grace a EOF)
        temp[i] = fgetc(ptr);
    }
    fclose(ptr);    //on ferme le fichier
    free(ptr);  //on libere le pointeur sur fichier

}

/// @brief Cette procédure permet de copier un tableau dans un fichier
/// @param[in] nom[] :  Nom du fichier choisi
/// @param[in] temp[] : Tableau à copier
/// @note **nom[]** sert aussi d’argument à la fonction **count** pour calculer la taille du fichier
/// @see count()
void copieDansFich(char nom[], char temp[]){
    long length = count(nom);   //on recupere le nombre d'octet et donc de caracteres
    FILE *ptr;
    ptr = fopen(nom , "w"); //on ouvre le fichier en mode Write
    for(int i = 0; i < length; i++){
        fputc(temp[i], ptr);
        //on met le caractere dans le fichier grace a fputc
        //on le fais pour tous les caracteres dans le tableau
    }
    fclose(ptr);    //on ferme le fichier
    free(ptr);  //on libere le pointeur sur fichier
}


/// @brief Cette procédure permet de copier un fichier dans un autre fichier
/// @param[in] nom_original[] : Nom du fichier à copier
/// @param[out] nom_copie[] : Nom du fichier où on copie **nom_original[]**
void copyFileToFile(char nom_original[], char nom_copie[]){
    FILE *ptr;
    FILE *ptr_copie;
    ptr = fopen(nom_original, "r"); //on ouvre le fichier qu'on souhaite copier en Read
    ptr_copie = fopen(nom_copie, "w");  //on ouvre le fichier destination en mode Write
    int c;  //ce caractere servira d'intermediaire
    while( (c = fgetc(ptr)) !=  (EOF) ){    //tant que le caractere recupere n'est pas la fin du fichier
        fputc(c, ptr_copie);    //copie le dans le fichier destination
    }
    //ferme les 2 fichiers
    fclose(ptr);
    fclose(ptr_copie);
    free(ptr);  //on libere le pointeur sur fichier
    free(ptr_copie);  //on libere le pointeur sur fichier
}



/// @brief Cette procédure permet d’ajouter des octets qui valent 0 afin que la longueur du tableau soit un multiple de 4 (padding).
/// @param[in] nom[] : Nom du fichier choisi
/// @note Si la longueur du fichier n’est pas un multiple de 4, on ne pourra pas traiter le fichier par bloc de 4 octets.
void Add(char nom[]){
    int add;    //variable dans laquelle on mettra ce qu'il faudra ajouter
    long length = count(nom);   //on recupere le nombre d'octet et donc de caracteres
    add = ( 4 - (length % 4) ) % 4; //on calcul le nombre d'ajouts a faire
    //on doit avoir un fichier de taille multile de 4
    if (add != 0)   //s'il faut ajouter quelque chose
    {
        char *temp = calloc(length, sizeof(char));   //on prepare le tableau dans lequel on va deverser le fichier
        copieDansTab(nom, temp); //on copie le tableau
        FILE *ptr;
        ptr = fopen(nom, "w");  //ouvre le fichier en mode write
        for(int i = 0; i < add ; i++)                      //on ajoute les blocs de 0000000 necessaires
        {
            fprintf(ptr, "%c", 0);
        }
        for(int i = 0; i < length ; i++)              //on rajoute le reste
        {
            fputc(temp[i], ptr);    //on copie le reste du tableau dans le fichier
        }
        fclose(ptr);    //on ferme le fichier
        //on free l'espace memoire utilise
        free(temp);
        free(ptr);
    }
}

/// @brief Enlever les octets qui valent 0, ajoutés par Add, afin de retrouver le fichier initial
/// @param[in] nom[] : Le nom du fichier
/// @see count()
void Remove(char nom[]){
    int add = 0;
    long length = count(nom);   //on recupere le nombre d'octet et donc de caracteres
    char *temp = calloc(length, sizeof(char));  //on prepare le tableau dans lequel on va deverser le fichier
    FILE *ptr;
    ptr = fopen(nom, "r");  //on ouvre le fichier en mode Read
    char c;
    //ce bloc for sert a determiner le nombre de 0 qu'on a ajouter dans le padding
    for(int i = 1 ; i < 4 ; i++){
        c = fgetc(ptr);
        if(c == 0) add++;
    }
    fclose(ptr);    //on ferme le fichier
    if (add != 0){  //s'il y a eu ajout
        ptr = fopen(nom, "r");  //on ouvre le fichier en mode Read
        int i;
        for(i = 0 ; i < add ; i++){
            fgetc(ptr); //on ignore les octets precedement ajoutes
        }
        while(i < length){
            temp[i-add] = fgetc(ptr);   //on copie le reste dans le tableau temp
            i++;
        }
        fclose(ptr);    //on ferme le fichier
        fopen(nom, "w");    //on ouvre le fichier en mode Write
        for(int j = 0; j < length-add ; j++)
        {
            fputc(temp[j], ptr);        //on replace le tableau dans le fichier (sans le fichier)
        }
        fclose(ptr);    //on ferme le fichier
        //on free l'espace memoire utilise
        free(temp);
        free(ptr);
    }
}

/// @brief Cette procédure permet de convertir un caractère de la représentation binaire (8 bits) en représentation dans la table ASCII
/// @param[in] *tab : Tableau (8 bits) contenant un caractère en représentation binaire
/// @param[out] *nombre : Pointeur sur le caractère
void binToChar(int *tab, char *nombre){  //transforme un tableau pour une representation binaire en un caractere
    int temp = 0;
    for(int i = 0 ; i < 8 ; i ++){
        temp += tab[7-i]*pow(2, i);
    }
    *nombre = (char)temp;
}
/// @brief Cette procédure permet de convertir un caractère exprimé dans la table ASCII sous forme binaire (8 bits)
/// @param[in] nombre : Un caractère
/// @param[out] *tab :  Tableau de 8 bits contenant le caractère sous forme binaire
void charToBin(int *tab, char nombre) {  //transforme un caractere en un tableau pour une representation binaire
    int temp = (int) nombre;
    int k;
    int i = 8;
    for (i = 7; i >= 0; i--)
    {
        k = temp >> i;

        if (k & 1)
            tab[7-i] = 1;
        else
            tab[7-i] = 0;
    }
}

/// @brief Cette procédure utilise un caractère **c** et un entier **i** afin de couper le caractère en deux puis décaler de **i** places à gauche les bits la première partie et de **i** places à droite les bits de la deuxième.
/// @brief La fonction finit par recoller les deux parties du caractère.
/// @param[in] c : Le caractère à chiffrer
/// @param[in] i : Le nombre de places à décaler les bits
/// @return Un nouveau caractère
/// @warning CypherChar était la première version de la génération de clés. Cette fonction n'est plus utilisée
//cypherChar etait la premier version de generation de cles ; cette methode n'est plus utilisee
char cypherChar(char c, int i){     //tu donnes un char et un nombre i et il permute i fois gauche et droite
    //on coupe notre caractere en 2 et on decale de i positions vers la droite
    unsigned char c_gauche = c >> 4;
    for(int j = 0; j < i ; j++){
        if (c_gauche%2 == 1){
            c_gauche = c_gauche >> 1;
            c_gauche = c_gauche +pow(2, 3);
        }
        else{
            c_gauche = c_gauche >> 1;
        }
        //on viens de remettre le 1 ou 0
    }
    c_gauche = c_gauche << 4;

    //on prend la partie droite et on decale de i positions vers la droite
    unsigned char c_droit = c << 4;
    c_droit = c_droit >> 4;
    //on defini la moitie droite (en effacant la gauche)
    for(int j = 0; j < i ; j++){
        if (c_droit % 2 == 1) {
            c_droit = c_droit >> 1;
            c_droit = c_droit + pow(2, 3);
        }else {
            c_droit = c_droit >> 1;
        }
        //on viens de remettre le 1 ou 0
    }
    return c_gauche + c_droit;
}


/// @brief Cette fonction permet la génération des sous-clés à partir d’un mot de passe saisi par l’utilisateur.
/// @brief Les sous-clés sont utilisées dans les fonctions 1 et 4.
/// @param[in] N : Nombre d’itérations
/// @param[in] password[] : Mot de passe saisi par l’utilisateur constitué de 8 caractères.
/// @param[out] ***keys[] : Tableau contenant les sous-clés générés (passage par adresse).
/// @warning keys[0] = password ; Donc ne pas utiliser keys[0]
/// @see Decallage()
void KeyGen(int N, const char password[], unsigned char ***keys[]){
    int L = 8;  //on sait que la longueur de la sous-cle est de 8 caracteres (on la met dans une variable pour peut-etre ameliorer plus tard)
    unsigned char *tab_gauche, *tab_droit;
    tab_gauche = calloc(L/2, sizeof(char)); //on prepare le gauche de la sous-cle
    tab_droit = calloc(L/2, sizeof(char));  //on prepare la partie droite de la sous-cle
    int i = 1;
    unsigned char temp[8];  //on definit un tableau de caracteres temporaire de taille 8
    strcpy(keys[0], password);  //keys[0] est toujours le mot de passe
    //c'est pour ca que dans les boucles, on part de 1 a = N et pas de 0 a < N
    strcpy(temp, keys[0]);  //on place aussi le mot de passe dans le tableau temporaire
    for(int j = 0 ; j < 4 ;j++){
        tab_gauche[j] = temp[j];    //on definit la partie gauche
    }

    for(int j = 4; j < 8 ;j++){
        tab_droit[j-4] = temp[j];   //on definit la partie droite
    }
    int decal[2];   //on a une taille de 2 ; l'une pour la partie gauche, l'autre pour la droite
    int decal_temp[2];  //on aura besoin de 2 tableaux de 2 qui vont s'update
    do{
        Decallage(decal,  tab_gauche, tab_droit, 3);    //on commence par decaler le dernier octet (3) le quatrieme
        for(int r = 0; r < 2; r++){
            decal_temp[r] = decal[r];   //on copie le contenu de decal dans decal_temp
        }

        Decallage(decal, tab_gauche, tab_droit, 0); //on decale le suivant
        if (decal_temp[0] == 1){    //si dans le decalage precedent on a 1, on met 1 : sinon 0 automatique
            tab_gauche[1]+= (int) pow(2, 7);    //+2^7 signifie 1 dans le bit fort
        }
        if (decal_temp[1] == 1){    //si dans le decalage precedent on a 1, on met 1 : sinon 0 automatique
            tab_droit[1]+= (int) pow(2, 7);
        }
        for(int r = 0; r < 2; r++){
            decal_temp[r] = decal[r];   //on copie le contenu de decal dans decal_temp
        }

        Decallage(decal, tab_gauche, tab_droit, 1); //on refais un decalage, on place le prochain dans le tableau decal
        if (decal_temp[0] == 1){    //on corrige le decalage relaif a cet octet
            tab_gauche[1]+= (int) pow(2, 7);
        }
        if (decal_temp[1] == 1){    //on corrige le decalage relaif a cet octet
            tab_droit[1]+= (int) pow(2, 7);
        }
        for(int r = 0; r < 2; r++){
            decal_temp[r] = decal[r];   //on copie le contenu de decal dans decal_temp
        }

        Decallage(decal, tab_gauche, tab_droit, 2); //on refais un decalage, on place le prochain dans le tableau decal
        if (decal_temp[0] == 1){    //on corrige le decalage relaif a cet octet
            tab_gauche[2]+= (int) pow(2, 7);
        }
        if (decal_temp[1] == 1){    //on corrige le decalage relaif a cet octet
            tab_droit[2]+= (int) pow(2, 7);
        }

        if (decal[0] == 1){ //on corrige le premier decalage realise, celui du 4e octet
            tab_gauche[3]+= (int) pow(2, 7);
        }
        if (decal[1] == 1){ //on corrige le premier decalage realise, celui du 4e octet
            tab_droit[3]+= (int) pow(2, 7);
        }

        strcpy(keys[i], tab_gauche);    //on copie la premiere partie de la sous-cle
        strcat( keys[i], tab_droit);    //on concatene avec la deuxieme partie de cette sous-cle
        //on a genere keys[i] la i-eme sous-cle
        i++;

    } while (i <= N);   //(tant que i <= N) on doit generer N sous cle avec i commencant a 1 ; voir declaration ligne 683
    free(tab_gauche);
    free(tab_droit);    //on libere les pointeurs sur fichiers
}

/// @brief Cette procédure aide à la génération des clés.
/// @brief Elle sert à décaler les bits d'un octet et à sauvegarder la valeur du bit faible (maintenant "disparu").
/// @param[in] *tab_gauche : la moitié gauche de la sous-clé
/// @param[in] *tab_droit : la moitié droite de la sous-clé
/// @param[in] i : le i -ème caractère des deux moitiés de sous-clés
/// @param[out] *decal : Le tableau qui donne les valeurs des 2 bits faibles qui sera mis dans les bits du prochain octet
void Decallage(int *decal ,unsigned char* tab_gauche, unsigned char* tab_droit, int i){
    unsigned char c = tab_gauche[i];
    //pour la partie gauche
    if(c%2 == 1){   //si le dernier bit = 1
        tab_gauche[i] = tab_gauche[i] >> 1; //on decale
        decal[0] = 1;   //on prend la valeur 1
    }
    else {  //si le dernier bit = 0
        tab_gauche[i] = tab_gauche[i] >> 1; //decale
        decal[0] = 0;   //on prend la valeur 0
    }

    //pour la partie droite
    c = tab_droit[i];
    if(c%2 == 1){   //si le dernier bit = 1
        tab_droit[i] = tab_droit[i] >> 1;   //on decale
        decal[1] = 1;   //on prend la valeur 1
    }
    else {  //si le dernier bit = 0
        tab_droit[i] = tab_droit[i] >> 1;   //on decale
        decal[1] = 0;   //on prend la valeur 0
    }
}

/// @brief Cette fonction retourne la valeur du bit suivant.
///
///@brief Elle est nécessaire surtout si le bit donne en paramètre est le 4e (=3). Dans ce cas-là on doit rendre le 1er bit (soit =0).
///
///@param i : La valeur du bit dont on souhaite trouver le prochain bit
///@return k : la valeur de bit suivant
///@warning Cette fonction n'est plus utilisée. On a renoncé à la mise en boucle du décalage.
///@warning On n'a donc plus besoin de cette fonction puisque tout est entrée "manuellement".
int prochain(int i){    //il donne le prochain octet : si i = 3 ; prochain = 0  on ne l'utilise plus dans le programme
    //i est l'entree, k la sortie
    int k;
    switch(i){
        case 0:
            k = 1;  //si i = 0 ; k = 1
            break;
        case 1:
            k = 2;  //si i = 1  ; k = 2
            break;
        case 2:
            k = 3;  //si i = 2 ; k = 3
            break;
        case 3:
            k = 0;  //si i = 3 ; k = 0
            break;
        default:
            k= -1;  //defailt "impossible" sinon il y a erreur
            break;
    }
    return k;
}
