# Intégration Android Java

Ce dossier contient le source d'un lecteur local de rapports, pas une APK compilée. Le moteur de scan reste dans Kali avec Python ; cette activité Android importe le JSON fourni par l'utilisateur. Aucune dépendance AndroidX ni permission réseau n'est nécessaire pour ce lecteur.

Dans un projet Android Java existant (SDK minimum 19), copier `AuditReportActivity.java` dans `app/src/main/java/com/tilex/audit/`. Ajouter à l'intérieur de `<application>` dans le manifeste :

```xml
<activity android:name="com.tilex.audit.AuditReportActivity" android:exported="false" />
```

Ouvrir cette activité depuis l'application avec :

```java
startActivity(new Intent(this, com.tilex.audit.AuditReportActivity.class));
```

Le lecteur utilise le sélecteur de fichiers Android, limite les imports à 2 Mo, désactive JavaScript et les chargements réseau, et échappe le contenu JSON avant affichage. Il ne transmet pas le rapport. Les rapports peuvent contenir des adresses internes : conserver et partager les fichiers selon les choix du propriétaire du réseau.

Ce source doit être compilé et testé dans le projet Android réel avant distribution. Il n'a pas été compilé dans cet environnement.
