rule Detect Malicious
{
        meta:
                Description = "This rule is made for detecting darkl0rd behaviour"
        strings:
                $host = "darkl0rd.com"
        condition:
                $host
}
