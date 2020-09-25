# define OktaResult class
# thanks /u/bis for the help
# https://www.reddit.com/r/PowerShell/comments/i06wi6/is_it_possible_to_extend_a_collection_object_with/fznrdkb/
class OktaResult : System.Collections.ArrayList {

    [uri]$SelfUri
    [uri]$NextUri
    [int]$RateLimit
    [int]$RemainingLimit
    [int]$SecondsToReset
    hidden [pscustomobject]$RawResponse

    OktaResult() {}
    OktaResult( [int]$Capacity ) : base( $Capacity ) {}
    OktaResult( [System.Collections.ICollection]$Collection ) : base( $Collection ) {}

}
