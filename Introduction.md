 # What is Firedancer?
**[Firedancer](https://jumpcrypto.com/firedancer/) is a validator node implementation written in C for the Solana blockchain**. Firedancer's core goals are:
- **Increased client diversity:** Firedancer will be the second fully-compliant Solana validator client. Diversity of client implementations makes the network more resilient to bugs in any one client implementation. 
- **Reliability:** Firedancer is being built from the ground up with reliability and network uptime in mind. 
- **Modularity:** Each major component of Firedancer is built to be used independently (or as independently as reasonable). This makes future feature development simple and maintainable. 
- **Perfomance:** The Firedancer validator will be faster than the Solana client and will make the network faster and more efficienet as a whole. Firedancer will be more efficient with system resources (CPU, RAM, disk space) while being faster than the Solana client. 
- ---
# Why Another Validator?
Firedancer will be solving some of the problems which solana as a network and community is trying to Solve.
1. **Compute Fee and gas fee estimation:** Firedancer's new and better block-packing algorithm is superior at predicting the number of compute units (CUs) used in a specific transaction. This makes it easier for validators to choose which transactions to include in the next block. ![image](https://user-images.githubusercontent.com/88841339/224479879-466202fb-d085-4c93-beb6-22d6c3885a44.png)

2. **Robustness**:When the validators are unable to reach consesnus and verify a transaction leading to a fork and downtime. One of the biggest memes floating around about Solana is its downtime, though it was a design tradeoff for it being the most performant blockchain, downtimes lead to a lot of different issues like liquidity, validator restarts etc which are mostly casued by small bugs in the updates in the core client code. 
When there are 2 client implementations and one of them faces a bug, the nodes running the bug free code will continue processing transactions to which the other nodes could sync to later. 
		
 # How?
 Firedancer has 3 high level Components which are modular and can be replaced with the components of Old Solana validator making it like different  components being stitched together while also writing a better documentation of the original validator client
- Components->
	- 	Packet Ingress
	- 	Runtime
	- 	Consensus

 ![image](https://user-images.githubusercontent.com/88841339/224098753-4a62136a-aad7-4343-89b0-f8c0fd45a990.png)

- # Why C?
	- When Building something like Firedancer which could potentially be run on thousands of machines, the code has to be efficient. C allows developers to write code which is tightly integrated with the hardware. C provides maximal flexibility to the developer in managing compute resources. [In this video](https://www.youtube.com/watch?v=9efhIs37hVI), Josh Siegel, one of the core contributors to Firedancer, explains in depth "why C?" for Firedancer, giving a practical demo to assist in the explanation.
- # Block propagation in Firedancer
	- ![Image](https://pbs.twimg.com/media/FmSWXByXwAAD1oH?format=jpg&name=4096x4096)

---
	
### More Information 
Links:
- [Announcement blog post](https://jumpcrypto.com/jump-vs-the-speed-of-light/)
- Breakpoint Talks by the legend KFB -> [General overview](https://www.youtube.com/watch?v=Dh6Yn2Odyr4)

	- [Deep Dive and first demo ](https://www.youtube.com/watch?v=YF-7duYCK54)
	
	- [Second Demo during the solana community call ](https://www.youtube.com/watch?v=zFS7MY4spBE)
			[The slides]
	- Link to the resentations ->
		- [Deep Dive](https://jump-assets.storage.googleapis.com/2022-11-06-bowers-et-al-deep-dive-final-embed-public.pdf)
		- [Intros](https://jump-assets.storage.googleapis.com/2022-11-05-bowers-et-al-hold-me-closer-frankendancer-breakpoint-2022-final-embed-public.pdf)
		 
	
	





