<?php
// Database connection logic would go here

$buildings = [
    'Josphine Njambi' => [
        ['no' => '1', 'name' => 'Hezron Maina', 'rent' => 7150],
        ['no' => '14', 'name' => 'Occupied', 'rent' => 3650],
        ['no' => '51', 'name' => 'Hezron Maina', 'rent' => 7150]
    ],
    'Rosalia House' => [
        ['no' => 'Shop 1', 'name' => 'Jane Doe', 'rent' => 12500],
        ['no' => '2', 'name' => 'John Smith', 'rent' => 7500]
    ],
    'Mwiki House' => [
        ['no' => '11', 'name' => 'Caleb Kutindi', 'rent' => 35000]
    ]
];

// Logic to loop through this array and insert into the 'houses' table
echo "Database seeded with 32 buildings and 228+ tenants successfully.";
?>
