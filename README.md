# routing-aware-dns
A program to resolve full-graph DNS and compute the BGP attack surface.

## USENIX 23 Artifact Evaluation Instructions
To evaluate this part of the artifact we have

1. A sample of domains from the logs shared with us from Let's Encrypt that can be used for the artifact evaluation.
2. The DNS lookup tool used to perform full graph DNS lookups on Let's Encrypt domains for our evaluation.
3. Our full collected DNS lookup dataset obtained by running this tool from multiple vantage points on sampled Let's Encrypt domains shortly after issuance.

We cannot share original raw log data from Let's Encrypt because privacy concerns as it contains sensitive user information. To avoid this and manage scaling for artifact evaluation, we have shared a sample of domain names and timestamps parsed from Let's Encrypt logs which is available in the data directory. The file `data/domains_random_samp.txt` contains 139754 domain names from the sample we took from Let's Encrypt logs. Based on our estimations, this will take a single core server running the code per the instructions below ~150h to perform. While this does produce a large sample for evaluation and results reproduction, we have also included a smaller sample in the file `data/domains_random_samp_small.txt` that contains 1397 domain names and can be completed in ~1.5h.

### Running the tool via docker

All dependencies can be installed via docker by building an image from the docker file included in the root dir this repo. Simply run:

```docker build --tag full-graph-dns-resolver .```

After making the docker image, run it in the background with:

```docker run --name dns-resolver -d full-graph-dns-resolver```

Enter the container to run commands:
```docker exec -it dns-resolver bash```

(this bash prompt can be exited and the container will still run for future use)

#### Cleanup commands after running

Kill the container:
```docker kill dns-resolver```

Remove the stopped container:
```docker rm dns-resolver```


# Collected DNS dataset for Let's Encrypt Subscriber Domains

The results of the DNS lookups (performed with this tool) on Let's Encrypt subscriber domains for all the domains we sampled in our paper can be found [here](https://secure-certificates.princeton.edu/dns_lookups_daily.tar.gz).
