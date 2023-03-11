 # What is Firedancer?
- **[Firedancer](https://jumpcrypto.com/firedancer/) is a node implementation written in C for the solana blockchain**. It will be the second full node implementation of Solana with the comping up Light Client Tinydancer. Firedancer will diversify the client stack and make the network more resilient as if there is an bug in the original rust node that halts the validators from producing blocks and coming to a consensus, validators running FD will keep the network secure and stable.
- ---
# Why Another Validator?
Firedancer will be solving some of the problems which solana is trying to 
 # How?
 Firedancer has 3 high level Components which are modular and can be replaced with the components of Old Solana validator making it like different  components being stitched together while also writing a better documentation of the original validator client
	- Components->
	  1. Packet Ingress
	  2. Runtime
	  3. Consensus

 ![image](https://user-images.githubusercontent.com/88841339/224098753-4a62136a-aad7-4343-89b0-f8c0fd45a990.png)

- # Why C?
	- When Building something like Firedancer which could potentially be run on thousands of machines, the code has to be efficient. C allows were tight integration with the hardware and make it allow developers a lot of flexibility in the ability to manage compute resources. [Here Josh Siegel](https://www.youtube.com/watch?v=9efhIs37hVI) one of the core builders of Firedancer explain in depth and practical demo on "why C"?
- # Block propagation in Firedancer
	- ![Image](https://pbs.twimg.com/media/FmSWXByXwAAD1oH?format=jpg&name=4096x4096)

---
	
### Wanna Learn more about firedancer? make sure to check out the [announcement](https://jumpcrypto.com/jump-vs-the-speed-of-light/) and the breakpoint talks.
- Breakpoint Talks by the legend KFB -> [General overview](https://www.youtube.com/watch?v=Dh6Yn2Odyr4)

	- [Deep Dive and first demo ](https://www.youtube.com/watch?v=YF-7duYCK54)
	
	- [Second Demo during the solana community call ](https://www.youtube.com/watch?v=zFS7MY4spBE)
			[The slides]
	- Link to the resentations ->
		- [Deep Dive](https://jump-assets.storage.googleapis.com/2022-11-06-bowers-et-al-deep-dive-final-embed-public.pdf)
		- [Intros](https://jump-assets.storage.googleapis.com/2022-11-05-bowers-et-al-hold-me-closer-frankendancer-breakpoint-2022-final-embed-public.pdf)
		 
	
	





