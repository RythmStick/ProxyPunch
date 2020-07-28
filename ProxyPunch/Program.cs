using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using NDesk.Options;
namespace ProxyPunch
{

    using static Globals;

    public static class Globals
    {
        public static Boolean help = false;
        public static Boolean verbose = false;
        public static string site = null;
        public static string issuer = null;
        public static string summary = System.Environment.NewLine;
        public static int maxCheckSites = 6;  // Number of sites to check in each category
        public static string userAgent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246";  // Customize to match browsers in target network
        public static string[,] urls = new string[,] // Array of sites to check which should be categorised as specified. These are the most commonly white-listed categories
            {
                {"Baseline","www.msn.com", "www.foxnews.com", "www.cbsnews.com", "www.yahoo.com", "www.wikipedia.org", "www.bbc.co.uk", "www.bing.com", "www.mapquest.com", "www.isbn.org", "yourdictionary.com", "www.stackoverflow.com", "thesaurus.com"},
                {"Health", "www.nhs.uk", "www.who.int","www.texmed.org","patient.info", "www.mlanet.org", "hetv.org", "www.ada.org","france-health.com","www.modernhealthcare.com","www.healthcaredive.com","www.bupa.co.uk","stanfordhealthcare.org"},
                {"Banking/finance", "www.wellsfargo.com", "www.capitalone.com","www.barclays.co.uk", "www.jpmorgan.com", "www.bankofengland.co.uk", "www.svb.com","www.lloydsbank.com", "www.crediteuropebank.com","www.bankofamerica.com","www.hsbc.com","www.usbank.com","www.citigroup.com"},
                {"Web-based email", "mail.rediff.com","www.gmx.com","www.hotmail.com", "www.gmail.com", "mail.com", "www.yahoomail.com", "www.outlook.com", "www.googlemail.com", "aolmail.com","protonmail.com","www.zohomail.com","webmail.123-reg.co.uk"},
            };
    }



    class Program
    {
        static void Main(string[] args)
        {
                      

            if (!validParameters(args))
            {
                return;
            }

            if (site!=null)
            {
                issuer = GetSingleIssuer(site);
                Console.WriteLine("[+] Issuing CA is {0}", issuer);
                return;


            }

                       
            urls = ShuffleArray(urls);  // Shuffle array so we dont always connect to same sites
            
            string proxyissuer = GetCommonIssuer(urls, maxCheckSites, 0);  // Try to enumerate the proxy servers issuing CA by enumerating certs for the 'general' sites

            if (proxyissuer == null && site==null)
            {
                Console.WriteLine("[-] Couldn't identify Proxy Issuing CA from baseline sites");
                return;

            }

            if (verbose)
            {
                Console.WriteLine("[+] Proxy issuing CA={0}",proxyissuer);
            }


            for (int i = 1; i < 4; i++)
            {
                string categoryissuer = GetCommonIssuer(urls, maxCheckSites, i);
                if (categoryissuer == proxyissuer)
                {
                    summary+="[-] No SSL Inspection bypass for "+urls[i, 0] + System.Environment.NewLine;
                }
                else if (categoryissuer == "Category Blocked") {
                    Console.WriteLine("[-] {0} probably blocked", urls[i, 0]);
                }
                else
                {
                    summary+="[+] SSL Inspection bypass for " + urls[i, 0] + System.Environment.NewLine;
                }
            }
            Console.WriteLine(summary);
        }

                     

        private static string GetSingleIssuer(string url)
        {
            string issuer = null;

            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls
    |       SecurityProtocolType.Tls11
    |       SecurityProtocolType.Tls12
    |       SecurityProtocolType.Ssl3;

            HttpWebRequest request = (HttpWebRequest)WebRequest.Create("https://" + url);

            IWebProxy proxy = request.Proxy;
            if (proxy.GetProxy(request.RequestUri).ToString().Substring(0, 8) != "https://")
            {
                string proxyuri = proxy.GetProxy(request.RequestUri).ToString();
                request.UseDefaultCredentials = true;
                request.Proxy = new WebProxy(proxyuri, false);
                request.Proxy.Credentials = System.Net.CredentialCache.DefaultCredentials;
            }

            request.UseDefaultCredentials = true;
            request.UserAgent = userAgent;
            request.Timeout = 5000;
            X509Certificate cert2 = null;
            HttpWebResponse response = null;

            try
            {
                response = (HttpWebResponse)request.GetResponse();
                X509Certificate cert = request.ServicePoint.Certificate;
                cert2 = new X509Certificate2(cert);
            }
            catch (Exception e)
            {
                if (verbose)
                {
                    Console.WriteLine("[-] Failed to connect to {0}",url);
                    return null;
                }
            }

            if (cert2 != null)
            {
                issuer = cert2.Issuer;
            }

            return issuer;
        }


        private static string[,] ShuffleArray(string[,] urls)
        {
            var rnd = new Random();
            for (int category = 0; category < 2; category++)
            {
                for (int i = 1; i < 11; ++i)
                {
                    int randomIndex = rnd.Next(1, 11);
                    string temp = urls[category, randomIndex];
                    urls[category, randomIndex] = urls[category, i];
                    urls[category, i] = temp;
                }
            }
            return urls;
        }



        private static string GetCommonIssuer(string[,] urls, int maxCheckSites, int index)
        {
            List<string> certissuers = new List<string>();
            for (int s = 1; s < maxCheckSites + 1; s++)
            {
                issuer = GetSingleIssuer(urls[index, s]);
           
                if (issuer != null)
                {
                    if (verbose)
                    {
                        Console.WriteLine("[+] Issuer={0}, Site={1}, Category={2}", issuer, urls[index, s], urls[index, 0]);
                    }
                    certissuers.Add(issuer);
                }
            }




            if (certissuers.Count==0)
            {
                return "Category Blocked";
            }


            var groupsWithCounts = from s in certissuers
                                   group s by s into g
                                   select new
                                   {
                                       Item = g.Key,
                                       Count = g.Count()
                                   };
            var groupsSorted = groupsWithCounts.OrderByDescending(g => g.Count);
            string mostFrequest = groupsSorted.First().Item;

            double issuerpc = (double)75 / 100 * maxCheckSites;

            if (groupsSorted.First().Count > issuerpc)
            {
                return certissuers[0];
            }
            else
            {
                return null;
            }
        }

        public static Boolean validParameters(string[] args)
        {
            var options = new OptionSet(){
                {"m|maxsites=", "Maximum sites to check in each category (increasing will improve accuracy)", (int o) => maxCheckSites = o},
                {"f|fqdn=", "check issuing CA for single site eg. www.microsoft.com (https:// will be added)", o => site = o},
                {"v|verbose","Increase Verbosity", o => verbose = true},
                {"h|?|help","Show Help", o => help = true},
            };

            try
            {
                options.Parse(args);
                if (help)
                {
                    showHelp(options);
                    return false;
                }

                if (maxCheckSites < 3 )
                {
                    Console.WriteLine("[-] maxsites must be > 2");
                    return false;
                }
                else if (maxCheckSites > (urls.Length/4)-1)
                {
                    Console.WriteLine("[-] maxsites must be < {0}",urls.Length/4);
                    return false;
                }
            }
            catch (Exception e)
            {
                Console.Error.WriteLine(e.Message);
                showHelp(options);
                return false;
            }


            if (site!=null && site.Substring(0,5)=="https://")
            {
                site = site.Replace("https://", "");
            }

            return true;
        }


        public static void showHelp(OptionSet p)
        {
            Console.WriteLine(@"                               ,--.--._");
            Console.WriteLine(@" ____  ____   __  _  _  _  _ -' _, \___)");
            Console.WriteLine(@"(  _ \(  _ \ /  \( \/ )( \/ )   / _/____)");
            Console.WriteLine(@" ) __/ )   /(  O ))  (  )  /    \//(____)");
            Console.WriteLine(@"(__)  (__\_) \__/(_/\_)(__/ --\     (__)");
            Console.WriteLine(@"                               `-----'");
            Console.WriteLine("@_RythmStick\n\n\n");
            Console.WriteLine("Find SSL inpection whitelisted categories through proxy\nUsage:");
            p.WriteOptionDescriptions(Console.Out);
        }

    }



}
