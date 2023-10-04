package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

func main() {
	sglist := os.Args[1:]
	// Load the Shared AWS Configuration (~/.aws/config)
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatal(err)
	}
	ec2client := ec2.NewFromConfig(cfg)

	resp, err := ec2client.DescribeSecurityGroups(context.TODO(), &ec2.DescribeSecurityGroupsInput{
		GroupIds: sglist, // pass the sg list obtained from security group
	})

	if err != nil {
		log.Fatalf("failed to list SGs, %v", err)
	}

	fmt.Println("Securit Group details:- ")

	for _, sg := range resp.SecurityGroups {
		fmt.Printf("%v", aws.ToString(sg.GroupName))
		//Ingress Rule Check
		fmt.Println("\n--IngressRules--")
		for _, sk := range sg.IpPermissions {
			//IPV4 check
			for _, sip := range sk.IpRanges {
				cidrip, _, err := net.ParseCIDR(aws.ToString(sip.CidrIp))
				if err != nil {
					log.Fatalf("failed to list SGs, %v", err)
				}
				if !cidrip.IsPrivate() {
					if strings.HasPrefix(aws.ToString(sip.CidrIp), "0.0.0.0") {
						fmt.Printf("\n Critical IP address of %v is Open to Internet IPV4 with port %v\n", aws.ToString(sg.GroupName), aws.ToInt32(sk.FromPort))
						continue
					}

					fmt.Printf("\n Warning!! SG %v's IP address  %v is not private IP, Might be a loopback or public IP with Port %v\n", aws.ToString(sg.GroupName), aws.ToString(sip.CidrIp), aws.ToInt32(sk.FromPort))

				}
			}
			//Ipv6 Check
			for _, sip := range sk.Ipv6Ranges {
				cidrip, _, err := net.ParseCIDR(aws.ToString(sip.CidrIpv6))
				if err != nil {
					log.Fatalf("failed to parse IP, %v", err)
				}
				if !cidrip.IsPrivate() {
					if strings.HasPrefix(aws.ToString(sip.CidrIpv6), "::") {
						fmt.Printf("\n Critical IP address of %v is Open to Internet IPV6 with port %v\n", aws.ToString(sg.GroupName), aws.ToInt32(sk.FromPort))
						continue
					}

					fmt.Printf("\n Warning!! SG %v's IP address  %v is not private IP, Might be a loopback or public IP with Port %v\n", aws.ToString(sg.GroupName), aws.ToString(sip.CidrIpv6), aws.ToInt32(sk.FromPort))

				}
			}

			//Egress Rules Check
			/*
				fmt.Println("\n--EgressRules--")
				for _, sk := range sg.IpPermissionsEgress {

					fmt.Printf("FromPort:- %v", aws.ToInt32(sk.FromPort))
					fmt.Printf("ToPort:- %v\n", aws.ToInt32(sk.ToPort))
				}
			*/
		}
	}

}
